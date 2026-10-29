/// @file        code_item.cpp
/// @brief       code_item 的结构解码与精确重编码实现。
#include "dex/code_item.hpp"

#include <unordered_map>
#include <vector>

#include "dex/bytes.hpp"
#include "dex/leb128.hpp"
#include "dex/reader.hpp"

namespace dex::core {

Result<CodeItem, ReadError> parseCodeItem(ByteSlice source, ca::u32 offset,
                                          ca::u32 typeCount,
                                          Diagnostics* diagnostics)
{
    if (offset >= source.size()) {
        return Err(ReadError::BadCodeItem);
    }

    const ca::core::Bytes bytes = ca::core::Bytes::from_static(source.data(), source.size());
    Result<Reader, ReadError> reader = Reader::at(bytes, offset);
    if (reader.is_err()) {
        return Err(ReadError::BadCodeItem);
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u16, ReadError> rr = cur.u16();
    const Result<ca::u16, ReadError> ri = cur.u16();
    const Result<ca::u16, ReadError> ro = cur.u16();
    const Result<ca::u16, ReadError> rt = cur.u16();
    const Result<ca::u32, ReadError> rd = cur.u32();
    const Result<ca::u32, ReadError> rn = cur.u32();
    if (rr.is_err() || ri.is_err() || ro.is_err() || rt.is_err() || rd.is_err() || rn.is_err()) {
        return Err(ReadError::BadCodeItem);
    }

    const ca::u16 registersSize = rr.unwrap();
    const ca::u16 insSize = ri.unwrap();
    const ca::u16 triesSize = rt.unwrap();
    const ca::u32 insnsSize = rn.unwrap();

    if (registersSize < insSize) {
        return Err(ReadError::BadCodeItem);
    }

    const ca::u64 insnsBytes = static_cast<ca::u64>(insnsSize) * 2u;
    const ca::u64 triesBytes = static_cast<ca::u64>(triesSize) * 8u;
    const ca::u64 padding = (triesSize != 0 && (insnsSize & 1u) != 0) ? 2u : 0u;
    const ca::u64 need = 16u + insnsBytes + padding + triesBytes;
    if (need > static_cast<ca::u64>(source.size() - offset)) {
        return Err(ReadError::BadCodeItem);
    }

    CodeItem item;
    item.offset = offset;
    item.debugInfoOff = rd.unwrap();
    item.registersSize = registersSize;
    item.insSize = insSize;
    item.outsSize = ro.unwrap();
    item.triesSize = triesSize;
    item.insnsSize = insnsSize;
    item.insns = ByteSpan{offset + 16u, static_cast<ca::u32>(insnsBytes)};
    item.tries = ByteSpan{offset + 16u + static_cast<ca::u32>(insnsBytes + padding),
                          static_cast<ca::u32>(triesBytes)};
    item.raw = ByteSpan{offset, static_cast<ca::u32>(need)};
    item.handlersOff = triesSize == 0
                           ? 0
                           : offset + 16u + static_cast<ca::u32>(insnsBytes + padding + triesBytes);

    if (triesSize == 0) {
        return Ok(std::move(item));
    }

    // 编码处理器表至少有一个 uleb128 计数；入口必须在文件内。
    if (item.handlersOff >= source.size()) {
        return Err(ReadError::BadCodeItem);
    }

    // ---- try_item 表 ----
    Result<Reader, ReadError> triesReader = Reader::at(bytes, item.tries.offset);
    if (triesReader.is_err()) {
        return Err(ReadError::BadCodeItem);
    }
    Reader triesCur = std::move(triesReader).unwrap();
    item.tryBlocks.reserve(triesSize);
    for (ca::u16 i = 0; i < triesSize; ++i) {
        const ca::usize entryOffset = triesCur.pos();
        const Result<ca::u32, ReadError> rs = triesCur.u32();
        const Result<ca::u16, ReadError> rc = triesCur.u16();
        const Result<ca::u16, ReadError> rh = triesCur.u16();
        if (rs.is_err() || rc.is_err() || rh.is_err()) {
            return Err(ReadError::BadCodeItem);
        }

        TryBlock block;
        block.startAddress = rs.unwrap();
        block.insnCount = rc.unwrap();
        block.handlerOff = rh.unwrap();
        if (static_cast<ca::u64>(block.startAddress) + block.insnCount > item.insnsSize) {
            if (diagnostics != nullptr) {
                diagnostics->warn(ReadError::BadCodeItem, static_cast<ca::u32>(entryOffset));
            }
        }
        item.tryBlocks.push_back(block);
    }

    // ---- encoded_catch_handler_list ----
    Result<Reader, ReadError> handlersReader = Reader::at(bytes, item.handlersOff);
    if (handlersReader.is_err()) {
        return Err(ReadError::BadCodeItem);
    }
    Reader handlersCur = std::move(handlersReader).unwrap();

    const Result<ca::u32, ReadError> rcount = readUleb128(handlersCur);
    if (rcount.is_err()) {
        return Err(ReadError::BadCodeItem);
    }
    const ca::u32 handlerCount = rcount.unwrap();
    // 每个 handler 至少 1 字节（sleb size），先按剩余字节封顶。
    if (handlerCount > handlersCur.remaining()) {
        return Err(ReadError::BadCodeItem);
    }

    std::unordered_map<ca::u32, ca::u32> indexByOffset;
    item.catchHandlers.reserve(handlerCount);
    for (ca::u32 i = 0; i < handlerCount; ++i) {
        const ca::u32 handlerOffset = static_cast<ca::u32>(handlersCur.pos() - item.handlersOff);

        const Result<ca::i32, ReadError> rsize = readSleb128(handlersCur);
        if (rsize.is_err()) {
            return Err(ReadError::BadCodeItem);
        }
        const ca::i32 signedCount = rsize.unwrap();
        const ca::i64 typedCount = signedCount > 0
                                       ? signedCount
                                       : -static_cast<ca::i64>(signedCount);

        // 每个 typed pair 由两个至少 1 字节的 uleb 组成。
        if (static_cast<ca::u64>(typedCount) * 2u > handlersCur.remaining()) {
            return Err(ReadError::BadCodeItem);
        }

        CatchHandler handler;
        handler.typed.reserve(static_cast<ca::usize>(typedCount));
        for (ca::i64 j = 0; j < typedCount; ++j) {
            const ca::usize typeOffset = handlersCur.pos();
            const Result<ca::u32, ReadError> rtype = readUleb128(handlersCur);
            if (rtype.is_err()) {
                return Err(ReadError::BadCodeItem);
            }
            const ca::u32 typeIdx = rtype.unwrap();

            const ca::usize addrOffset = handlersCur.pos();
            const Result<ca::u32, ReadError> raddr = readUleb128(handlersCur);
            if (raddr.is_err()) {
                return Err(ReadError::BadCodeItem);
            }
            const ca::u32 address = raddr.unwrap();

            if (typeCount != 0 && typeIdx >= typeCount) {
                if (diagnostics != nullptr) {
                    diagnostics->warn(ReadError::BadIndex, static_cast<ca::u32>(typeOffset));
                }
            }
            if (address >= item.insnsSize) {
                if (diagnostics != nullptr) {
                    diagnostics->warn(ReadError::BadCodeItem, static_cast<ca::u32>(addrOffset));
                }
            }
            handler.typed.push_back(TypedCatch{typeIdx, address});
        }

        // 负值或 0 表示后跟 catch-all：abs(size) 是 typed 数量，catch-all 单独编码。
        if (signedCount <= 0) {
            const ca::usize addrOffset = handlersCur.pos();
            const Result<ca::u32, ReadError> raddr = readUleb128(handlersCur);
            if (raddr.is_err()) {
                return Err(ReadError::BadCodeItem);
            }
            handler.hasCatchAll = true;
            handler.catchAllAddress = raddr.unwrap();
            if (handler.catchAllAddress >= item.insnsSize) {
                if (diagnostics != nullptr) {
                    diagnostics->warn(ReadError::BadCodeItem, static_cast<ca::u32>(addrOffset));
                }
            }
        }

        indexByOffset.emplace(handlerOffset, static_cast<ca::u32>(item.catchHandlers.size()));
        item.catchHandlers.push_back(std::move(handler));
    }

    item.handlers = ByteSpan{item.handlersOff,
                             static_cast<ca::u32>(handlersCur.pos() - item.handlersOff)};

    for (TryBlock& block : item.tryBlocks) {
        const auto it = indexByOffset.find(block.handlerOff);
        if (it == indexByOffset.end()) {
            return Err(ReadError::BadCodeItem);
        }
        block.handlerIndex = it->second;
    }

    return Ok(std::move(item));
}

Result<std::vector<ca::u8>, WriteError> writeCodeItem(const CodeItem& item, ByteSlice insns)
{
    const ca::u64 expectedBytes = static_cast<ca::u64>(item.insnsSize) * 2u;
    if (insns.size() != expectedBytes ||
        item.tryBlocks.size() != static_cast<ca::usize>(item.triesSize)) {
        return Err(WriteError::Unencodable);
    }

    std::vector<ca::u8> out;
    appendU16(out, item.registersSize);
    appendU16(out, item.insSize);
    appendU16(out, item.outsSize);
    appendU16(out, item.triesSize);
    appendU32(out, item.debugInfoOff);
    appendU32(out, item.insnsSize);
    if (!insns.empty()) {
        out.insert(out.end(), insns.data(), insns.data() + insns.size());
    }

    if (item.triesSize == 0) {
        if (!item.catchHandlers.empty()) {
            return Err(WriteError::Unencodable);
        }
        return Ok(std::move(out));
    }

    if ((item.insnsSize & 1u) != 0) {
        appendU16(out, 0);  // insns 奇数 code unit 时，tries 前补 2 字节
    }

    std::vector<ca::u8> handlers;
    if (item.catchHandlers.size() > 0xFFFFFFFFu) {
        return Err(WriteError::Unencodable);
    }
    writeUleb128(handlers, static_cast<ca::u32>(item.catchHandlers.size()));
    std::vector<ca::u32> handlerOffsets;
    handlerOffsets.reserve(item.catchHandlers.size());
    for (const CatchHandler& handler : item.catchHandlers) {
        if (!handler.hasCatchAll && handler.typed.empty()) {
            return Err(WriteError::Unencodable);
        }
        if (handler.typed.size() > 0x7FFFFFFFu) {
            return Err(WriteError::Unencodable);
        }
        handlerOffsets.push_back(static_cast<ca::u32>(handlers.size()));
        const ca::i32 signedCount =
            handler.hasCatchAll ? -static_cast<ca::i32>(handler.typed.size())
                                : static_cast<ca::i32>(handler.typed.size());
        writeSleb128(handlers, signedCount);
        for (const TypedCatch& typed : handler.typed) {
            writeUleb128(handlers, typed.typeIdx);
            writeUleb128(handlers, typed.address);
        }
        if (handler.hasCatchAll) {
            writeUleb128(handlers, handler.catchAllAddress);
        }
    }

    for (const TryBlock& block : item.tryBlocks) {
        if (block.handlerIndex >= handlerOffsets.size()) {
            return Err(WriteError::Unencodable);
        }
        const ca::u32 handlerOff = handlerOffsets[block.handlerIndex];
        if (handlerOff > 0xFFFFu) {
            return Err(WriteError::Unencodable);
        }
        appendU32(out, block.startAddress);
        appendU16(out, block.insnCount);
        appendU16(out, static_cast<ca::u16>(handlerOff));
    }

    out.insert(out.end(), handlers.begin(), handlers.end());
    return Ok(std::move(out));
}

}   // namespace dex::core
