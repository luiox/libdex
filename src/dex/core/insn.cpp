/// @file        insn.cpp
/// @brief       DEX 指令流解码实现。
#include "dex/core/insn.hpp"

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

void appendU16(std::vector<ca::u8>& out, ca::u16 value)
{
    out.push_back(static_cast<ca::u8>(value & 0xFFu));
    out.push_back(static_cast<ca::u8>(value >> 8));
}

void appendU32(std::vector<ca::u8>& out, ca::u32 value)
{
    appendU16(out, static_cast<ca::u16>(value & 0xFFFFu));
    appendU16(out, static_cast<ca::u16>(value >> 16));
}

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

bool fitsU4(ca::u64 value) noexcept { return value <= 0xFu; }
bool fitsU8(ca::u64 value) noexcept { return value <= 0xFFu; }
bool fitsU16(ca::u64 value) noexcept { return value <= 0xFFFFu; }
bool fitsU32(ca::u64 value) noexcept { return value <= 0xFFFFFFFFu; }
bool fitsI4(ca::i64 value) noexcept { return value >= -8 && value <= 7; }
bool fitsI8(ca::i64 value) noexcept { return value >= -128 && value <= 127; }
bool fitsI16(ca::i64 value) noexcept { return value >= -32768 && value <= 32767; }
bool fitsI32(ca::i64 value) noexcept
{
    return value >= -2147483647LL - 1 && value <= 2147483647LL;
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
