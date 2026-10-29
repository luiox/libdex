/// @file        insn.cpp
/// @brief       DEX 指令流解码实现。
#include "dex/insn.hpp"

#include "dex/bytes.hpp"

namespace dex::core {

namespace {

/// payload 标识，取 AOSP DEX 规范值：packed 0x0100、sparse 0x0200、fill 0x0300。
/// 注意 0x0101 不是 ident——它是 `move vA, vB`（A=0,B=1）的合法编码；曾按
/// 0x0101 识别导致真实文件里的 move 指令被误判成 payload（d8 实测语料拦截）。
constexpr ca::u16 kPackedSwitchIdent = 0x0100;
constexpr ca::u16 kSparseSwitchIdent = 0x0200;
constexpr ca::u16 kFillArrayIdent = 0x0300;

ca::u16 readU16(const ca::u8* p) noexcept
{
    return static_cast<ca::u16>(static_cast<ca::u16>(p[0]) |
                                static_cast<ca::u16>(static_cast<ca::u16>(p[1]) << 8));
}

ca::u32 readU32(const ca::u8* p) noexcept
{
    return static_cast<ca::u32>(p[0]) | (static_cast<ca::u32>(p[1]) << 8) |
           (static_cast<ca::u32>(p[2]) << 16) | (static_cast<ca::u32>(p[3]) << 24);
}

ca::u64 readU64(const ca::u8* p) noexcept
{
    return static_cast<ca::u64>(readU32(p)) | (static_cast<ca::u64>(readU32(p + 4)) << 32);
}

/// @brief 把 value 的低 bits 位按补码符号扩展。
ca::i32 signExtend(ca::u32 value, ca::u32 bits) noexcept
{
    if (bits >= 32) {
        return static_cast<ca::i32>(value);
    }
    const ca::u32 sign = 1u << (bits - 1);
    return static_cast<ca::i32>((value ^ sign) - sign);
}

struct CodeUnits
{
    const ca::u8* data = nullptr;
    ca::u32 units = 0;

    ca::u16 at(ca::u32 index) const noexcept { return readU16(data + static_cast<ca::usize>(index) * 2); }
    ca::u32 u32At(ca::u32 index) const noexcept
    {
        return readU32(data + static_cast<ca::usize>(index) * 2);
    }
    ca::u64 u64At(ca::u32 index) const noexcept
    {
        return readU64(data + static_cast<ca::usize>(index) * 2);
    }
    ByteSlice bytesAt(ca::u32 unitOffset, ca::usize byteLength) const noexcept
    {
        return ByteSlice{data + static_cast<ca::usize>(unitOffset) * 2, byteLength};
    }
};

/// @brief 解析 payload 头部与变长区；调用方保证 address 为偶数。
Result<Insn, InsnError> decodePayload(const CodeUnits& code, ca::u32 address)
{
    const ca::u32 remaining = code.units - address;
    const ca::u16 ident = code.at(address);

    Insn ins;
    ins.address = address;
    ins.opcode = 0;
    ins.format = InsnFormat::Payload;

    if (ident == kPackedSwitchIdent) {
        if (remaining < 4) {
            return Err(InsnError::Truncated);
        }
        const ca::u16 size = code.at(address + 1);
        const ca::u32 width = 4u + static_cast<ca::u32>(size) * 2u;
        if (remaining < width) {
            return Err(InsnError::Truncated);
        }
        ins.payloadKind = PayloadKind::PackedSwitch;
        ins.payloadCount = size;
        ins.payloadFirstKey = signExtend(code.u32At(address + 2), 32);
        ins.payloadData = code.bytesAt(address + 4, static_cast<ca::usize>(size) * 4u);
        ins.width = width;
        ins.raw = code.bytesAt(address, static_cast<ca::usize>(width) * 2u);
        return Ok(ins);
    }

    if (ident == kSparseSwitchIdent) {
        if (remaining < 2) {
            return Err(InsnError::Truncated);
        }
        const ca::u16 size = code.at(address + 1);
        const ca::u32 width = 2u + static_cast<ca::u32>(size) * 4u;
        if (remaining < width) {
            return Err(InsnError::Truncated);
        }
        ins.payloadKind = PayloadKind::SparseSwitch;
        ins.payloadCount = size;
        ins.payloadData = code.bytesAt(address + 2, static_cast<ca::usize>(size) * 8u);
        ins.width = width;
        ins.raw = code.bytesAt(address, static_cast<ca::usize>(width) * 2u);
        return Ok(ins);
    }

    // 0x0300 fill-array-data
    if (ident != kFillArrayIdent) {
        return Err(InsnError::BadPayload);
    }
    if (remaining < 4) {
        return Err(InsnError::Truncated);
    }
    const ca::u16 elementWidth = code.at(address + 1);
    const ca::u32 count = code.u32At(address + 2);
    if (elementWidth == 0 && count != 0) {
        return Err(InsnError::BadPayload);
    }
    const ca::u64 dataBytes = static_cast<ca::u64>(count) * elementWidth;
    const ca::u64 width = 4u + (dataBytes + 1u) / 2u;  // 数据区补齐到 code unit 边界
    if (width > remaining) {
        return Err(InsnError::Truncated);
    }
    ins.payloadKind = PayloadKind::FillArrayData;
    ins.payloadCount = count;
    ins.payloadElementWidth = elementWidth;
    ins.payloadData = code.bytesAt(address + 4, static_cast<ca::usize>(dataBytes));
    ins.width = static_cast<ca::u32>(width);
    ins.raw = code.bytesAt(address, static_cast<ca::usize>(width) * 2u);
    return Ok(ins);
}

void decodeOperands(const CodeUnits& code, Insn& ins) noexcept
{
    const ca::u32 address = ins.address;
    const ca::u16 u0 = code.at(address);
    const ca::u16 u1 = ins.width >= 2 ? code.at(address + 1) : 0;
    const ca::u16 u2 = ins.width >= 3 ? code.at(address + 2) : 0;

    switch (ins.format) {
    case InsnFormat::F10x:
        break;
    case InsnFormat::F12x:
        ins.registers[0] = (u0 >> 8) & 0x0Fu;
        ins.registers[1] = (u0 >> 12) & 0x0Fu;
        ins.registerCount = 2;
        break;
    case InsnFormat::F11n:
        ins.registers[0] = (u0 >> 8) & 0x0Fu;
        ins.registerCount = 1;
        ins.literal = signExtend((u0 >> 12) & 0x0Fu, 4);
        break;
    case InsnFormat::F11x:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        break;
    case InsnFormat::F10t:
        ins.branchOffset = signExtend(u0 >> 8, 8);
        break;
    case InsnFormat::F20t:
        ins.branchOffset = signExtend(u1, 16);
        break;
    case InsnFormat::F22x:
        ins.registers[0] = u0 >> 8;
        ins.registers[1] = u1;
        ins.registerCount = 2;
        break;
    case InsnFormat::F21t:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.branchOffset = signExtend(u1, 16);
        break;
    case InsnFormat::F21s:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.literal = signExtend(u1, 16);
        break;
    case InsnFormat::F21h:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        // const-wide/high16 的高 16 位要落在 48 位处；乘法避免负值左移的未定义行为。
        ins.literal = static_cast<ca::i64>(signExtend(u1, 16)) *
                      (ins.opcode == 0x19 ? 0x0001000000000000LL : 0x10000LL);
        break;
    case InsnFormat::F21c:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.index = u1;
        break;
    case InsnFormat::F23x:
        ins.registers[0] = u0 >> 8;
        ins.registers[1] = u1 & 0xFFu;
        ins.registers[2] = u1 >> 8;
        ins.registerCount = 3;
        break;
    case InsnFormat::F22b:
        ins.registers[0] = u0 >> 8;
        ins.registers[1] = u1 & 0xFFu;
        ins.registerCount = 2;
        ins.literal = signExtend(u1 >> 8, 8);
        break;
    case InsnFormat::F22t:
        ins.registers[0] = (u0 >> 8) & 0x0Fu;
        ins.registers[1] = (u0 >> 12) & 0x0Fu;
        ins.registerCount = 2;
        ins.branchOffset = signExtend(u1, 16);
        break;
    case InsnFormat::F22s:
        ins.registers[0] = (u0 >> 8) & 0x0Fu;
        ins.registers[1] = (u0 >> 12) & 0x0Fu;
        ins.registerCount = 2;
        ins.literal = signExtend(u1, 16);
        break;
    case InsnFormat::F22c:
        ins.registers[0] = (u0 >> 8) & 0x0Fu;
        ins.registers[1] = (u0 >> 12) & 0x0Fu;
        ins.registerCount = 2;
        ins.index = u1;
        break;
    case InsnFormat::F30t:
        ins.branchOffset = static_cast<ca::i32>(code.u32At(address + 1));
        break;
    case InsnFormat::F32x:
        ins.registers[0] = u1;
        ins.registers[1] = u2;
        ins.registerCount = 2;
        break;
    case InsnFormat::F31i:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.literal = signExtend(code.u32At(address + 1), 32);
        break;
    case InsnFormat::F31t:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.branchOffset = static_cast<ca::i32>(code.u32At(address + 1));
        break;
    case InsnFormat::F31c:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.index = code.u32At(address + 1);
        break;
    case InsnFormat::F35c:
        // unit0 = A|G|op：A 是高 nibble（参数个数），G 是 bits 11..8（第五个寄存器）。
        ins.registerCount = u0 >> 12;
        ins.registers[0] = u2 & 0x0Fu;
        ins.registers[1] = (u2 >> 4) & 0x0Fu;
        ins.registers[2] = (u2 >> 8) & 0x0Fu;
        ins.registers[3] = (u2 >> 12) & 0x0Fu;
        ins.registers[4] = (u0 >> 8) & 0x0Fu;
        ins.index = u1;
        break;
    case InsnFormat::F3rc:
        ins.registerCount = u0 >> 8;
        ins.startRegister = u2;
        ins.index = u1;
        break;
    case InsnFormat::F45cc:
        // 同 35c：A 在高 nibble，G 在 bits 11..8。
        ins.registerCount = u0 >> 12;
        ins.registers[0] = u2 & 0x0Fu;
        ins.registers[1] = (u2 >> 4) & 0x0Fu;
        ins.registers[2] = (u2 >> 8) & 0x0Fu;
        ins.registers[3] = (u2 >> 12) & 0x0Fu;
        ins.registers[4] = (u0 >> 8) & 0x0Fu;
        ins.index = u1;
        ins.protoIndex = code.at(address + 3);
        ins.hasProtoIndex = true;
        break;
    case InsnFormat::F4rcc:
        ins.registerCount = u0 >> 8;
        ins.startRegister = u2;
        ins.index = u1;
        ins.protoIndex = code.at(address + 3);
        ins.hasProtoIndex = true;
        break;
    case InsnFormat::F51l:
        ins.registers[0] = u0 >> 8;
        ins.registerCount = 1;
        ins.literal = static_cast<ca::i64>(code.u64At(address + 1));
        break;
    case InsnFormat::Unknown:
    case InsnFormat::Payload:
        break;
    }
}

}   // namespace

Result<std::vector<Insn>, InsnError> decodeInsns(ByteSlice insns)
{
    if (insns.size() % 2 != 0) {
        return Err(InsnError::Truncated);
    }

    CodeUnits code{insns.data(), static_cast<ca::u32>(insns.size() / 2)};
    std::vector<Insn> decoded;

    ca::u32 address = 0;
    while (address < code.units) {
        const ca::u16 unit0 = code.at(address);
        const ca::u8 opcode = static_cast<ca::u8>(unit0 & 0xFFu);

        if (unit0 == kPackedSwitchIdent || unit0 == kSparseSwitchIdent ||
            unit0 == kFillArrayIdent) {
            if ((address & 1u) != 0) {
                return Err(InsnError::BadPayload);
            }
            const Result<Insn, InsnError> payload = decodePayload(code, address);
            if (payload.is_err()) {
                return Err(payload.unwrap_err());
            }
            Insn ins = payload.unwrap();
            address += ins.width;
            decoded.push_back(ins);
            continue;
        }
        if (opcode == 0x00) {
            // ART 把低字节为 0 的 code unit 一律当作 nop；高字节非零也接受。
            Insn ins;
            ins.address = address;
            ins.width = 1;
            ins.opcode = 0;
            ins.format = InsnFormat::F10x;
            ins.raw = code.bytesAt(address, 2);
            decoded.push_back(ins);
            ++address;
            continue;
        }

        const OpcodeInfo& info = opcodeInfo(opcode);
        if (!info.isDefined()) {
            return Err(InsnError::UnknownOpcode);
        }
        const ca::u32 width = insnWidth(info.format);
        if (code.units - address < width) {
            return Err(InsnError::Truncated);
        }

        Insn ins;
        ins.address = address;
        ins.width = width;
        ins.opcode = opcode;
        ins.format = info.format;
        ins.indexKind = info.indexKind;
        decodeOperands(code, ins);
        ins.raw = code.bytesAt(address, static_cast<ca::usize>(width) * 2u);
        address += width;
        decoded.push_back(ins);
    }

    return Ok(std::move(decoded));
}

namespace {

void appendU64(std::vector<ca::u8>& out, ca::u64 value)
{
    appendU32(out, static_cast<ca::u32>(value & 0xFFFFFFFFu));
    appendU32(out, static_cast<ca::u32>(value >> 32));
}

void appendSlice(std::vector<ca::u8>& out, ByteSlice bytes)
{
    if (bytes.empty()) {
        return;
    }
    out.insert(out.end(), bytes.data(), bytes.data() + bytes.size());
}

/// @brief 10x/20t/30t/32x 的 unit0 高位不承载语义；源字节仍是同一 opcode 时沿用。
ca::u16 unusedHighByte(const Insn& insn) noexcept
{
    if (insn.raw.size() >= 2 && insn.raw[0] == insn.opcode) {
        return insn.raw[1];
    }
    return 0;
}

Result<void, InsnEncodeError> encodePayload(const Insn& insn, std::vector<ca::u8>& out)
{
    switch (insn.payloadKind) {
    case PayloadKind::PackedSwitch: {
        const ca::u64 dataBytes = static_cast<ca::u64>(insn.payloadCount) * 4u;
        if (insn.payloadCount > 0xFFFFu || insn.payloadData.size() != dataBytes) {
            return Err(InsnEncodeError::BadPayload);
        }
        appendU16(out, kPackedSwitchIdent);
        appendU16(out, static_cast<ca::u16>(insn.payloadCount));
        appendU32(out, static_cast<ca::u32>(insn.payloadFirstKey));
        appendSlice(out, insn.payloadData);
        return Ok();
    }
    case PayloadKind::SparseSwitch: {
        const ca::u64 dataBytes = static_cast<ca::u64>(insn.payloadCount) * 8u;
        if (insn.payloadCount > 0xFFFFu || insn.payloadData.size() != dataBytes) {
            return Err(InsnEncodeError::BadPayload);
        }
        appendU16(out, kSparseSwitchIdent);
        appendU16(out, static_cast<ca::u16>(insn.payloadCount));
        appendSlice(out, insn.payloadData);
        return Ok();
    }
    case PayloadKind::FillArrayData: {
        if (insn.payloadElementWidth == 0 && insn.payloadCount != 0) {
            return Err(InsnEncodeError::BadPayload);
        }
        const ca::u64 dataBytes =
            static_cast<ca::u64>(insn.payloadCount) * insn.payloadElementWidth;
        if (insn.payloadData.size() != dataBytes) {
            return Err(InsnEncodeError::BadPayload);
        }
        appendU16(out, kFillArrayIdent);
        appendU16(out, insn.payloadElementWidth);
        appendU32(out, insn.payloadCount);
        appendSlice(out, insn.payloadData);
        if ((dataBytes & 1u) != 0) {
            // 数据区补齐字节不属于载荷内容；源字节存在时原样沿用。
            ca::u8 pad = 0;
            const ca::usize padAt = 8u + static_cast<ca::usize>(dataBytes);
            if (insn.raw.size() > padAt && insn.raw[0] == 0x00 && insn.raw[1] == 0x03) {
                pad = insn.raw[padAt];
            }
            out.push_back(pad);
        }
        return Ok();
    }
    case PayloadKind::None:
        break;
    }
    return Err(InsnEncodeError::BadPayload);
}

}   // namespace

Result<void, InsnEncodeError> encodeInsn(const Insn& insn, std::vector<ca::u8>& out)
{
    if (insn.format == InsnFormat::Payload) {
        return encodePayload(insn, out);
    }

    const OpcodeInfo& info = opcodeInfo(insn.opcode);
    if (!info.isDefined() || info.format != insn.format) {
        return Err(InsnEncodeError::BadFormat);
    }

    const ca::u16 op = insn.opcode;
    const ca::u16 hi = unusedHighByte(insn);
    const ca::u16 a = insn.registers[0];

    switch (insn.format) {
    case InsnFormat::F10x:
        appendU16(out, static_cast<ca::u16>(op | (hi << 8)));
        return Ok();
    case InsnFormat::F12x:
        if (!fitsU4(a) || !fitsU4(insn.registers[1])) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8) | (insn.registers[1] << 12)));
        return Ok();
    case InsnFormat::F11n:
        if (!fitsU4(a) || !fitsI4(insn.literal)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8) |
                                           ((static_cast<ca::u16>(insn.literal) & 0xFu) << 12)));
        return Ok();
    case InsnFormat::F11x:
        if (!fitsU8(a)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        return Ok();
    case InsnFormat::F10t:
        if (!fitsI8(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(
                          op | ((static_cast<ca::u16>(insn.branchOffset) & 0xFFu) << 8)));
        return Ok();
    case InsnFormat::F20t:
        if (!fitsI16(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (hi << 8)));
        appendU16(out, static_cast<ca::u16>(insn.branchOffset));
        return Ok();
    case InsnFormat::F22x:
        if (!fitsU8(a) || !fitsU16(insn.registers[1])) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, insn.registers[1]);
        return Ok();
    case InsnFormat::F21t:
        if (!fitsU8(a) || !fitsI16(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(insn.branchOffset));
        return Ok();
    case InsnFormat::F21s:
        if (!fitsU8(a) || !fitsI16(insn.literal)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(insn.literal));
        return Ok();
    case InsnFormat::F21h: {
        if (!fitsU8(a)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        // high16 的观测语义是寄存器原始位模式（32/64 位的高 16 位 = u1，
        // 其余为 0）：接受完整位模式书写（如 const/high16 的 0xffff0000），
        // 按 16 位半字自然截断；低 16+ 位非零或超出位宽才拒绝。
        const unsigned shift = insn.opcode == 0x19 ? 48u : 16u;
        const ca::u64 raw = static_cast<ca::u64>(insn.literal);
        const bool fitsWidth = insn.opcode == 0x19 ||
                               (insn.literal >= -0x80000000LL && insn.literal <= 0xFFFFFFFFLL);
        const ca::u64 u1 = (raw >> shift) & 0xFFFFu;
        if (!fitsWidth || (raw & ((static_cast<ca::u64>(1) << shift) - 1u)) != 0) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(u1));
        return Ok();
    }
    case InsnFormat::F21c:
        if (!fitsU8(a) || !fitsU16(insn.index)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        return Ok();
    case InsnFormat::F23x:
        if (!fitsU8(a) || !fitsU8(insn.registers[1]) || !fitsU8(insn.registers[2])) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(insn.registers[1] |
                                            (insn.registers[2] << 8)));
        return Ok();
    case InsnFormat::F22b:
        if (!fitsU8(a) || !fitsU8(insn.registers[1]) || !fitsI8(insn.literal)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU16(out, static_cast<ca::u16>(
                          insn.registers[1] |
                          ((static_cast<ca::u16>(insn.literal) & 0xFFu) << 8)));
        return Ok();
    case InsnFormat::F22t:
        if (!fitsU4(a) || !fitsU4(insn.registers[1]) || !fitsI16(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8) | (insn.registers[1] << 12)));
        appendU16(out, static_cast<ca::u16>(insn.branchOffset));
        return Ok();
    case InsnFormat::F22s:
        if (!fitsU4(a) || !fitsU4(insn.registers[1]) || !fitsI16(insn.literal)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8) | (insn.registers[1] << 12)));
        appendU16(out, static_cast<ca::u16>(insn.literal));
        return Ok();
    case InsnFormat::F22c:
        if (!fitsU4(a) || !fitsU4(insn.registers[1]) || !fitsU16(insn.index)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8) | (insn.registers[1] << 12)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        return Ok();
    case InsnFormat::F30t:
        if (!fitsI32(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (hi << 8)));
        appendU32(out, static_cast<ca::u32>(insn.branchOffset));
        return Ok();
    case InsnFormat::F32x:
        if (!fitsU16(a) || !fitsU16(insn.registers[1])) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (hi << 8)));
        appendU16(out, a);
        appendU16(out, insn.registers[1]);
        return Ok();
    case InsnFormat::F31i:
        if (!fitsU8(a) || !fitsI32(insn.literal)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU32(out, static_cast<ca::u32>(insn.literal));
        return Ok();
    case InsnFormat::F31t:
        if (!fitsU8(a) || !fitsI32(insn.branchOffset)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU32(out, static_cast<ca::u32>(insn.branchOffset));
        return Ok();
    case InsnFormat::F31c:
        if (!fitsU8(a) || !fitsU32(insn.index)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU32(out, insn.index);
        return Ok();
    case InsnFormat::F35c: {
        if (insn.registerCount > 15 || !fitsU16(insn.index)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        for (ca::u32 i = 0; i < 5; ++i) {
            if (!fitsU4(insn.registers[i])) {
                return Err(InsnEncodeError::OperandOverflow);
            }
        }
        appendU16(out, static_cast<ca::u16>(op | (insn.registers[4] << 8) |
                                            (insn.registerCount << 12)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        appendU16(out, static_cast<ca::u16>(
                          insn.registers[0] | (insn.registers[1] << 4) |
                          (insn.registers[2] << 8) | (insn.registers[3] << 12)));
        return Ok();
    }
    case InsnFormat::F3rc: {
        if (!fitsU16(insn.index)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (insn.registerCount << 8)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        appendU16(out, insn.startRegister);
        return Ok();
    }
    case InsnFormat::F45cc: {
        if (insn.registerCount > 15 || !fitsU16(insn.index) || !fitsU16(insn.protoIndex)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        for (ca::u32 i = 0; i < 5; ++i) {
            if (!fitsU4(insn.registers[i])) {
                return Err(InsnEncodeError::OperandOverflow);
            }
        }
        appendU16(out, static_cast<ca::u16>(op | (insn.registers[4] << 8) |
                                            (insn.registerCount << 12)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        appendU16(out, static_cast<ca::u16>(
                          insn.registers[0] | (insn.registers[1] << 4) |
                          (insn.registers[2] << 8) | (insn.registers[3] << 12)));
        appendU16(out, static_cast<ca::u16>(insn.protoIndex));
        return Ok();
    }
    case InsnFormat::F4rcc: {
        if (!fitsU16(insn.index) || !fitsU16(insn.protoIndex)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (insn.registerCount << 8)));
        appendU16(out, static_cast<ca::u16>(insn.index));
        appendU16(out, insn.startRegister);
        appendU16(out, static_cast<ca::u16>(insn.protoIndex));
        return Ok();
    }
    case InsnFormat::F51l:
        if (!fitsU8(a)) {
            return Err(InsnEncodeError::OperandOverflow);
        }
        appendU16(out, static_cast<ca::u16>(op | (a << 8)));
        appendU64(out, static_cast<ca::u64>(insn.literal));
        return Ok();
    case InsnFormat::Payload:
    case InsnFormat::Unknown:
        break;
    }
    return Err(InsnEncodeError::BadFormat);
}

Result<std::vector<ca::u8>, InsnEncodeError> encodeInsns(const std::vector<Insn>& insns)
{
    std::vector<ca::u8> out;
    for (const Insn& insn : insns) {
        if (insn.format == InsnFormat::Payload && (out.size() % 4u) != 0) {
            return Err(InsnEncodeError::MisalignedPayload);
        }
        const Result<void, InsnEncodeError> written = encodeInsn(insn, out);
        if (written.is_err()) {
            return Err(written.unwrap_err());
        }
    }
    return Ok(std::move(out));
}

ca::i32 Insn::packedSwitchTarget(ca::u32 i) const noexcept
{
    return static_cast<ca::i32>(readU32(payloadData.data() + static_cast<ca::usize>(i) * 4u));
}

ca::i32 Insn::sparseSwitchKey(ca::u32 i) const noexcept
{
    return static_cast<ca::i32>(readU32(payloadData.data() + static_cast<ca::usize>(i) * 4u));
}

ca::i32 Insn::sparseSwitchTarget(ca::u32 i) const noexcept
{
    return static_cast<ca::i32>(
        readU32(payloadData.data() + (static_cast<ca::usize>(payloadCount) + i) * 4u));
}

const char* to_string(InsnError e) noexcept
{
    switch (e) {
    case InsnError::Ok:
        return "Ok";
    case InsnError::Truncated:
        return "Truncated";
    case InsnError::UnknownOpcode:
        return "UnknownOpcode";
    case InsnError::BadPayload:
        return "BadPayload";
    }
    return "Unknown";
}

const char* to_string(InsnEncodeError e) noexcept
{
    switch (e) {
    case InsnEncodeError::Ok:
        return "Ok";
    case InsnEncodeError::BadFormat:
        return "BadFormat";
    case InsnEncodeError::OperandOverflow:
        return "OperandOverflow";
    case InsnEncodeError::BadPayload:
        return "BadPayload";
    case InsnEncodeError::MisalignedPayload:
        return "MisalignedPayload";
    }
    return "Unknown";
}

}   // namespace dex::core
