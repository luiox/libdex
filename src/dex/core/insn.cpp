/// @file        insn.cpp
/// @brief       DEX 指令流解码实现。
#include "dex/core/insn.hpp"

namespace dex::core {

namespace {

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

    if (ident == 0x0100) {
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
        return Ok(ins);
    }

    if (ident == 0x0200) {
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
        return Ok(ins);
    }

    // 0x0300 fill-array-data
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
        ins.registerCount = (u0 >> 8) & 0x0Fu;
        ins.registers[0] = u2 & 0x0Fu;
        ins.registers[1] = (u2 >> 4) & 0x0Fu;
        ins.registers[2] = (u2 >> 8) & 0x0Fu;
        ins.registers[3] = (u2 >> 12) & 0x0Fu;
        ins.registers[4] = u0 >> 12;
        ins.index = u1;
        break;
    case InsnFormat::F3rc:
        ins.registerCount = u0 >> 8;
        ins.startRegister = u2;
        ins.index = u1;
        break;
    case InsnFormat::F45cc:
        ins.registerCount = (u0 >> 8) & 0x0Fu;
        ins.registers[0] = u2 & 0x0Fu;
        ins.registers[1] = (u2 >> 4) & 0x0Fu;
        ins.registers[2] = (u2 >> 8) & 0x0Fu;
        ins.registers[3] = (u2 >> 12) & 0x0Fu;
        ins.registers[4] = u0 >> 12;
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

        if (opcode == 0x00) {
            if (unit0 == 0x0100 || unit0 == 0x0200 || unit0 == 0x0300) {
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
            // ART 把低字节为 0 的 code unit 一律当作 nop；高字节非零也接受。
            Insn ins;
            ins.address = address;
            ins.width = 1;
            ins.opcode = 0;
            ins.format = InsnFormat::F10x;
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
        address += width;
        decoded.push_back(ins);
    }

    return Ok(std::move(decoded));
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

}   // namespace dex::core
