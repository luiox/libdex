/// @file        insn_edit.cpp
/// @brief       指令编辑原语的实现：分支目标、寄存器域、地址重算与 payload 构造。
#include "dex/insn_edit.hpp"

#include "dex/bytes.hpp"

namespace dex::core {

bool constFormFits(ConstForm form, ca::i64 value) noexcept
{
    switch (form) {
        case ConstForm::Const4:
            return fitsI4(value);
        case ConstForm::Const16:
            return fitsI16(value);
        case ConstForm::Const:
            return fitsI32(value);
        case ConstForm::ConstHigh16:
            return fitsI32(value) && (static_cast<ca::u64>(value) & 0xFFFFu) == 0;
        case ConstForm::ConstWide16:
            return fitsI16(value);
        case ConstForm::ConstWide32:
            return fitsI32(value);
        case ConstForm::ConstWideHigh16:
            return (static_cast<ca::u64>(value) & 0xFFFFFFFFFFFFull) == 0;
        case ConstForm::ConstWide:
            return true;
    }
    return false;
}

ca::u32 insnIndexLimit(InsnFormat format) noexcept
{
    switch (format) {
        case InsnFormat::F21c:
        case InsnFormat::F22c:
        case InsnFormat::F35c:
        case InsnFormat::F3rc:
        case InsnFormat::F45cc:
        case InsnFormat::F4rcc:
            return 0xFFFFu;
        case InsnFormat::F31c:
            return 0xFFFFFFFFu;
        default:
            return 0;
    }
}

ca::i64 insnBranchTarget(const Insn& insn) noexcept
{
    return static_cast<ca::i64>(insn.address) + static_cast<ca::i64>(insn.branchOffset);
}

Result<void, InsnEncodeError> setInsnBranchTarget(Insn& insn, ca::i64 target) noexcept
{
    if (!insn.isBranch()) {
        return Err(InsnEncodeError::BadFormat);
    }

    const ca::i64 offset = target - static_cast<ca::i64>(insn.address);
    bool fits = false;
    switch (insn.format) {
        case InsnFormat::F10t:
            fits = fitsI8(offset);
            break;
        case InsnFormat::F20t:
        case InsnFormat::F21t:
        case InsnFormat::F22t:
            fits = fitsI16(offset);
            break;
        case InsnFormat::F30t:
        case InsnFormat::F31t:
            fits = fitsI32(offset);
            break;
        default:
            return Err(InsnEncodeError::BadFormat);
    }
    if (!fits) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    insn.branchOffset = static_cast<ca::i32>(offset);
    return Ok();
}

Result<void, InsnEncodeError> recomputeInsnAddresses(std::vector<Insn>& insns)
{
    ca::u64 next = 0;
    for (Insn& insn : insns) {
        if (next > 0xFFFFFFFFu) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        insn.address = static_cast<ca::u32>(next);

        ca::u32 width = 0;
        if (insn.format == InsnFormat::Payload) {
            width = insn.width;
            if (width == 0) {
                return Err(InsnEncodeError::BadPayload);
            }
        } else {
            const OpcodeInfo& info = opcodeInfo(insn.opcode);
            if (!info.isDefined() || info.format != insn.format) {
                return Err(InsnEncodeError::BadFormat);
            }
            width = insnWidth(insn.format);
            insn.width = width;
        }
        next += width;
    }
    if (next > 0xFFFFFFFFu) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    return Ok();
}

// ---- adapter 原语：寄存器域与 payload 构造 ----

namespace {

/// List 布局第 slot 槽的域宽（位）；槽位不存在返回 0。
ca::u32 listSlotBits(const Insn& insn, ca::u32 slot) noexcept
{
    switch (insn.format) {
        case InsnFormat::F12x:
        case InsnFormat::F22t:
        case InsnFormat::F22s:
        case InsnFormat::F22c:
            return slot < 2 ? 4 : 0;
        case InsnFormat::F11n:
            return slot == 0 ? 4 : 0;
        case InsnFormat::F11x:
        case InsnFormat::F21t:
        case InsnFormat::F21s:
        case InsnFormat::F21h:
        case InsnFormat::F21c:
        case InsnFormat::F31i:
        case InsnFormat::F31t:
        case InsnFormat::F31c:
        case InsnFormat::F51l:
            return slot == 0 ? 8 : 0;
        case InsnFormat::F22x:
            return slot == 0 ? 8 : (slot == 1 ? 16 : 0);
        case InsnFormat::F23x:
            return slot < 3 ? 8 : 0;
        case InsnFormat::F22b:
            return slot < 2 ? 8 : 0;
        case InsnFormat::F32x:
            return slot < 2 ? 16 : 0;
        case InsnFormat::F35c:
        case InsnFormat::F45cc:
            return slot < insn.registerCount && slot < 5 ? 4 : 0;
        default:
            return 0;
    }
}

void appendI32(std::vector<ca::u8>& out, ca::i32 value)
{
    appendU32(out, static_cast<ca::u32>(value));
}

}   // namespace

RegisterLayout insnRegisterLayout(const Insn& insn) noexcept
{
    switch (insn.format) {
        case InsnFormat::F3rc:
        case InsnFormat::F4rcc:
            return RegisterLayout::Range;
        case InsnFormat::F12x:
        case InsnFormat::F11n:
        case InsnFormat::F11x:
        case InsnFormat::F22x:
        case InsnFormat::F21t:
        case InsnFormat::F21s:
        case InsnFormat::F21h:
        case InsnFormat::F21c:
        case InsnFormat::F23x:
        case InsnFormat::F22b:
        case InsnFormat::F22t:
        case InsnFormat::F22s:
        case InsnFormat::F22c:
        case InsnFormat::F32x:
        case InsnFormat::F31i:
        case InsnFormat::F31t:
        case InsnFormat::F31c:
        case InsnFormat::F35c:
        case InsnFormat::F45cc:
        case InsnFormat::F51l:
            return RegisterLayout::List;
        default:
            return RegisterLayout::None;
    }
}

ca::u32 insnRegisterTotal(const Insn& insn) noexcept
{
    switch (insnRegisterLayout(insn)) {
        case RegisterLayout::List:
        case RegisterLayout::Range:
            return insn.registerCount;
        default:
            return 0;
    }
}

ca::u16 insnRegisterAt(const Insn& insn, ca::u32 i) noexcept
{
    if (insnRegisterLayout(insn) == RegisterLayout::Range) {
        return static_cast<ca::u16>(insn.startRegister + i);
    }
    return i < 5 ? insn.registers[i] : 0;
}

Result<void, InsnEncodeError> setInsnRegister(Insn& insn, ca::u32 i, ca::u16 reg) noexcept
{
    if (insnRegisterLayout(insn) != RegisterLayout::List) {
        return Err(InsnEncodeError::BadFormat);
    }
    const ca::u32 bits = listSlotBits(insn, i);
    if (bits == 0 || reg > ((1u << bits) - 1u)) {
        return Err(bits == 0 ? InsnEncodeError::BadFormat : InsnEncodeError::OperandOverflow);
    }
    insn.registers[i] = reg;
    return Ok();
}

Result<void, InsnEncodeError> setInsnRegisterRange(Insn& insn, ca::u16 start,
                                                   ca::u16 count) noexcept
{
    if (insnRegisterLayout(insn) != RegisterLayout::Range) {
        return Err(InsnEncodeError::BadFormat);
    }
    if (count > 0xFFu) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    insn.startRegister = start;
    insn.registerCount = static_cast<ca::u8>(count);
    return Ok();
}

ca::u32 insnRegisterCeiling(const std::vector<Insn>& insns) noexcept
{
    ca::u32 ceiling = 0;
    for (const Insn& insn : insns) {
        if (insnRegisterLayout(insn) == RegisterLayout::Range) {
            const ca::u32 end =
                static_cast<ca::u32>(insn.startRegister) + insn.registerCount;
            if (end > ceiling) {
                ceiling = end;
            }
            continue;
        }
        const ca::u32 total = insnRegisterTotal(insn);
        for (ca::u32 i = 0; i < total; ++i) {
            const ca::u32 end = static_cast<ca::u32>(insnRegisterAt(insn, i)) + 1u;
            if (end > ceiling) {
                ceiling = end;
            }
        }
    }
    return ceiling;
}

Result<void, InsnEncodeError> shiftInsnRegisters(std::vector<Insn>& insns,
                                                 ca::i32 delta) noexcept
{
    if (delta == 0) {
        return Ok();
    }
    for (Insn& insn : insns) {
        const RegisterLayout layout = insnRegisterLayout(insn);
        if (layout == RegisterLayout::None) {
            continue;
        }
        if (layout == RegisterLayout::Range) {
            const ca::i64 start = static_cast<ca::i64>(insn.startRegister) + delta;
            const ca::i64 end = start + insn.registerCount;
            if (start < 0 || end > 0x10000u) {
                return Err(InsnEncodeError::OperandOverflow);
            }
            insn.startRegister = static_cast<ca::u16>(start);
            continue;
        }
        const ca::u32 total = insnRegisterTotal(insn);
        for (ca::u32 i = 0; i < total; ++i) {
            const ca::i64 shifted = static_cast<ca::i64>(insn.registers[i]) + delta;
            if (shifted < 0 || shifted > 0xFFFFu) {
                return Err(InsnEncodeError::OperandOverflow);
            }
            const Result<void, InsnEncodeError> set =
                setInsnRegister(insn, i, static_cast<ca::u16>(shifted));
            if (set.is_err()) {
                return set;
            }
        }
    }
    return Ok();
}

Result<void, InsnEncodeError> remapInsnRegisters(
    std::vector<Insn>& insns, const std::vector<ca::u16>& mapping) noexcept
{
    for (Insn& insn : insns) {
        const RegisterLayout layout = insnRegisterLayout(insn);
        if (layout == RegisterLayout::None) {
            continue;
        }
        if (layout == RegisterLayout::Range) {
            const ca::u32 start = insn.startRegister;
            if (static_cast<ca::usize>(start) >= mapping.size() ||
                static_cast<ca::usize>(start) + insn.registerCount > mapping.size()) {
                return Err(InsnEncodeError::OperandOverflow);
            }
            const ca::u16 mappedStart = mapping[start];
            for (ca::u32 k = 1; k < insn.registerCount; ++k) {
                if (static_cast<ca::u32>(mapping[start + k]) !=
                    static_cast<ca::u32>(mappedStart) + k) {
                    // 区间上映射不是平移；不平移的重排需改 35c 形态，归 adapter。
                    return Err(InsnEncodeError::BadFormat);
                }
            }
            insn.startRegister = mappedStart;
            continue;
        }
        const ca::u32 total = insnRegisterTotal(insn);
        for (ca::u32 i = 0; i < total; ++i) {
            const ca::u16 from = insn.registers[i];
            if (static_cast<ca::usize>(from) >= mapping.size()) {
                return Err(InsnEncodeError::OperandOverflow);
            }
            const Result<void, InsnEncodeError> set = setInsnRegister(insn, i, mapping[from]);
            if (set.is_err()) {
                return set;
            }
        }
    }
    return Ok();
}

Result<PayloadInsn, InsnEncodeError> makePackedSwitchPayload(
    ca::i32 firstKey, const std::vector<ca::i32>& targets)
{
    // 宽度 4+2n 个 code unit，size 域 16 位。
    if (targets.size() > (65535u - 4u) / 2u) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    PayloadInsn payload;
    payload.storage.reserve(targets.size() * 4u);
    for (ca::i32 target : targets) {
        appendI32(payload.storage, target);
    }
    Insn& insn = payload.insn;
    insn.format = InsnFormat::Payload;
    insn.payloadKind = PayloadKind::PackedSwitch;
    insn.payloadCount = static_cast<ca::u32>(targets.size());
    insn.payloadFirstKey = firstKey;
    insn.payloadData = ByteSlice{payload.storage.data(), payload.storage.size()};
    insn.width = 4u + static_cast<ca::u32>(targets.size()) * 2u;
    return Ok(std::move(payload));
}

Result<PayloadInsn, InsnEncodeError> makeSparseSwitchPayload(
    const std::vector<ca::i32>& keys, const std::vector<ca::i32>& targets)
{
    if (keys.size() != targets.size()) {
        return Err(InsnEncodeError::BadPayload);
    }
    for (ca::usize i = 1; i < keys.size(); ++i) {
        if (keys[i] <= keys[i - 1]) {
            return Err(InsnEncodeError::BadPayload);  // ART 按二分查找解释
        }
    }
    // 宽度 2+4n 个 code unit，size 域 16 位。
    if (keys.size() > (65535u - 2u) / 4u) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    PayloadInsn payload;
    payload.storage.reserve(keys.size() * 8u);
    for (ca::i32 key : keys) {
        appendI32(payload.storage, key);
    }
    for (ca::i32 target : targets) {
        appendI32(payload.storage, target);
    }
    Insn& insn = payload.insn;
    insn.format = InsnFormat::Payload;
    insn.payloadKind = PayloadKind::SparseSwitch;
    insn.payloadCount = static_cast<ca::u32>(keys.size());
    insn.payloadData = ByteSlice{payload.storage.data(), payload.storage.size()};
    insn.width = 2u + static_cast<ca::u32>(keys.size()) * 4u;
    return Ok(std::move(payload));
}

Result<PayloadInsn, InsnEncodeError> makeFillArrayDataPayload(
    ca::u16 elementWidth, std::vector<ca::u8> data)
{
    if (elementWidth == 0 && !data.empty()) {
        return Err(InsnEncodeError::BadPayload);
    }
    if (elementWidth != 0 && data.size() % elementWidth != 0) {
        return Err(InsnEncodeError::BadPayload);
    }
    // 宽度 4+ceil(bytes/2) 个 code unit，size 域 16 位。
    const ca::u64 width = 4u + (static_cast<ca::u64>(data.size()) + 1u) / 2u;
    if (width > 65535u) {
        return Err(InsnEncodeError::OperandOverflow);
    }
    PayloadInsn payload;
    payload.storage = std::move(data);
    Insn& insn = payload.insn;
    insn.format = InsnFormat::Payload;
    insn.payloadKind = PayloadKind::FillArrayData;
    insn.payloadElementWidth = elementWidth;
    insn.payloadCount = elementWidth == 0
                            ? 0u
                            : static_cast<ca::u32>(payload.storage.size() / elementWidth);
    insn.payloadData = ByteSlice{payload.storage.data(), payload.storage.size()};
    insn.width = static_cast<ca::u32>(width);
    return Ok(std::move(payload));
}

}   // namespace dex::core
