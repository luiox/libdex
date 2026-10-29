/// @file        debug_info.cpp
/// @brief       debug_info_item 的状态机解码与重编码。
#include "dex/debug_info.hpp"

#include <utility>

#include "dex/leb128.hpp"

namespace dex::core {

namespace {

Result<Reader, ReadError> readerAt(ByteSlice source, ca::u32 offset)
{
    const ca::core::Bytes bytes = ca::core::Bytes::from_static(source.data(), source.size());
    return Reader::at(bytes, offset);
}

}   // namespace

Result<DebugInfo, ReadError> readDebugInfo(ByteSlice source, ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    DebugInfo info;
    const Result<ca::u32, ReadError> lineStart = readUleb128(cur);
    if (lineStart.is_err()) {
        return Err(lineStart.unwrap_err());
    }
    info.lineStart = lineStart.unwrap();

    const Result<ca::u32, ReadError> parameterCount = readUleb128(cur);
    if (parameterCount.is_err()) {
        return Err(parameterCount.unwrap_err());
    }
    // 每个参数名至少一个 uleb 字节。
    if (parameterCount.unwrap() > cur.remaining()) {
        return Err(ReadError::Truncated);
    }
    info.parameterNames.reserve(parameterCount.unwrap());
    for (ca::u32 i = 0; i < parameterCount.unwrap(); ++i) {
        const Result<ca::u32, ReadError> name = readUleb128(cur);
        if (name.is_err()) {
            return Err(name.unwrap_err());
        }
        info.parameterNames.push_back(name.unwrap());
    }
    info.headerRaw = subOrEmpty(source, offset, cur.pos() - offset);

    while (true) {
        const ca::usize opStart = cur.pos();
        const Result<ca::u8, ReadError> opcode = cur.u8();
        if (opcode.is_err()) {
            return Err(opcode.unwrap_err());
        }
        if (opcode.unwrap() == kDbgEndSequence) {
            break;
        }

        DebugOp op;
        op.opcode = opcode.unwrap();

        if (op.opcode == kDbgAdvancePc) {
            const Result<ca::u32, ReadError> value = readUleb128(cur);
            if (value.is_err()) {
                return Err(value.unwrap_err());
            }
            op.addressDiff = value.unwrap();
        } else if (op.opcode == kDbgAdvanceLine) {
            const Result<ca::i32, ReadError> value = readSleb128(cur);
            if (value.is_err()) {
                return Err(value.unwrap_err());
            }
            op.lineDiff = value.unwrap();
        } else if (op.opcode == kDbgStartLocal || op.opcode == kDbgStartLocalExtended) {
            const Result<ca::u32, ReadError> reg = readUleb128(cur);
            const Result<ca::u32, ReadError> name = readUleb128(cur);
            const Result<ca::u32, ReadError> type = readUleb128(cur);
            if (reg.is_err() || name.is_err() || type.is_err()) {
                return Err(ReadError::Truncated);
            }
            op.reg = reg.unwrap();
            op.nameIdx = name.unwrap();
            op.typeIdx = type.unwrap();
            if (op.opcode == kDbgStartLocalExtended) {
                const Result<ca::u32, ReadError> sig = readUleb128(cur);
                if (sig.is_err()) {
                    return Err(sig.unwrap_err());
                }
                op.sigIdx = sig.unwrap();
            }
        } else if (op.opcode == kDbgEndLocal || op.opcode == kDbgRestartLocal) {
            const Result<ca::u32, ReadError> reg = readUleb128(cur);
            if (reg.is_err()) {
                return Err(reg.unwrap_err());
            }
            op.reg = reg.unwrap();
        } else if (op.opcode == kDbgSetFile) {
            const Result<ca::u32, ReadError> name = readUleb128(cur);
            if (name.is_err()) {
                return Err(name.unwrap_err());
            }
            op.nameIdx = name.unwrap();
        } else if (op.opcode != kDbgSetPrologueEnd && op.opcode != kDbgSetEpilogueBegin) {
            op.addressDiff = debugSpecialAddressDiff(op.opcode);
            op.lineDiff = debugSpecialLineDiff(op.opcode);
        }

        op.raw = subOrEmpty(source, opStart, cur.pos() - opStart);
        info.ops.push_back(op);
    }

    info.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(info));
}

Result<std::vector<ca::u8>, WriteError> writeDebugInfo(const DebugInfo& info)
{
    std::vector<ca::u8> out;

    if (!info.headerRaw.empty()) {
        out.insert(out.end(), info.headerRaw.data(),
                   info.headerRaw.data() + info.headerRaw.size());
    } else {
        if (info.parameterNames.size() > 0xFFFFFFFFu) {
            return Err(WriteError::Unencodable);
        }
        writeUleb128(out, info.lineStart);
        writeUleb128(out, static_cast<ca::u32>(info.parameterNames.size()));
        for (ca::u32 name : info.parameterNames) {
            writeUleb128(out, name);
        }
    }

    for (const DebugOp& op : info.ops) {
        if (op.opcode == kDbgEndSequence) {
            return Err(WriteError::Unencodable);
        }
        if (!op.raw.empty()) {
            out.insert(out.end(), op.raw.data(), op.raw.data() + op.raw.size());
            continue;
        }

        out.push_back(op.opcode);

        if (op.opcode == kDbgAdvancePc) {
            writeUleb128(out, op.addressDiff);
        } else if (op.opcode == kDbgAdvanceLine) {
            writeSleb128(out, op.lineDiff);
        } else if (op.opcode == kDbgStartLocal || op.opcode == kDbgStartLocalExtended) {
            writeUleb128(out, op.reg);
            writeUleb128(out, op.nameIdx);
            writeUleb128(out, op.typeIdx);
            if (op.opcode == kDbgStartLocalExtended) {
                writeUleb128(out, op.sigIdx);
            }
        } else if (op.opcode == kDbgEndLocal || op.opcode == kDbgRestartLocal) {
            writeUleb128(out, op.reg);
        } else if (op.opcode == kDbgSetFile) {
            writeUleb128(out, op.nameIdx);
        } else if (op.isSpecial()) {
            if (op.addressDiff != debugSpecialAddressDiff(op.opcode) ||
                op.lineDiff != debugSpecialLineDiff(op.opcode)) {
                return Err(WriteError::Unencodable);
            }
        }
    }

    out.push_back(kDbgEndSequence);
    return Ok(std::move(out));
}

}   // namespace dex::core
