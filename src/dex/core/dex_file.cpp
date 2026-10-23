/// @file        dex_file.cpp
/// @brief       DexFile 的 lazy 解码与查询实现。
#include "dex/core/dex_file.hpp"

#include <cstring>
#include <unordered_map>

#include "dex/core/leb128.hpp"

namespace dex::core {

namespace {

/// @brief 成员差分展开：首个条目用 diff 本身，之后必须严格递增。
Result<ca::u32, ReadError> nextMemberIndex(ca::u32 diff, ca::u32 previous, bool first) noexcept
{
    if (first) {
        return Ok(diff);
    }
    if (diff == 0) {
        return Err(ReadError::BadClassData);  // 重复索引
    }
    if (previous > 0xFFFFFFFFu - diff) {
        return Err(ReadError::BadClassData);  // 溢出
    }
    return Ok(previous + diff);
}

}   // namespace

void DexFile::adoptSource(ByteSlice bytes)
{
    if (bytes.empty()) {
        sourceBytes_ = ca::core::Bytes{};
        return;
    }
    sourceBytes_ = ca::core::Bytes::copy_from_slice(bytes.data(), bytes.size());
}

void DexFile::adoptBorrowedSource(ByteSlice bytes) noexcept
{
    sourceBytes_ = ca::core::Bytes::from_static(bytes.data(), bytes.size());
}

const MapItem* DexFile::findMapItem(MapType type) const noexcept
{
    for (const MapItem& item : mapItems) {
        if (item.type == type) {
            return &item;
        }
    }
    return nullptr;
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::string(ca::u32 index)
{
    if (index >= stringIds.size()) {
        return Err(ReadError::BadIndex);
    }

    if (stringCache_.size() != stringIds.size()) {
        stringCache_.resize(stringIds.size());
    }
    LazyString& slot = stringCache_[index];
    if (slot.state == LazyString::State::Decoded) {
        return Ok(slot.view);
    }
    if (slot.state == LazyString::State::Failed) {
        return Err(slot.error);
    }

    const auto fail = [&slot](ReadError e) -> Result<jstr::MUtf8StringRef, ReadError> {
        slot.state = LazyString::State::Failed;
        slot.error = e;
        return Err(e);
    };

    const ca::u32 offset = stringIds[index].dataOff;
    Result<Reader, ReadError> reader = Reader::at(sourceBytes_, offset);
    if (reader.is_err()) {
        return fail(ReadError::BadStringData);
    }
    Reader cur = std::move(reader).unwrap();

    // utf16_size 只用于定位字节起点；本阶段不做 UTF-16 长度校验。
    const Result<ca::u32, ReadError> len = readUleb128(cur);
    if (len.is_err()) {
        return fail(len.unwrap_err());
    }

    const ca::usize start = cur.pos();
    const ca::usize sourceSize = sourceBytes_.len();
    if (start >= sourceSize) {
        return fail(ReadError::BadStringData);
    }
    const ca::u8* base = sourceBytes_.as_ptr();
    const void* nul = std::memchr(base + start, 0, sourceSize - start);
    if (nul == nullptr) {
        return fail(ReadError::BadStringData);
    }
    const ca::usize end = static_cast<const ca::u8*>(nul) - base;

    slot.view = jstr::MUtf8StringRef(reinterpret_cast<const char*>(base + start), end - start);
    slot.state = LazyString::State::Decoded;
    return Ok(slot.view);
}

const jstr::MUtf8StringRef* DexFile::peekString(ca::u32 index) const noexcept
{
    if (index >= stringCache_.size()) {
        return nullptr;
    }
    const LazyString& slot = stringCache_[index];
    return slot.state == LazyString::State::Decoded ? &slot.view : nullptr;
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::typeDescriptor(ca::u32 typeIdx)
{
    if (typeIdx >= typeIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return string(typeIds[typeIdx].descriptorIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::classDescriptor(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeDescriptor(classDefs[classDefIdx].classIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::superclassDescriptor(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    const ca::u32 superIdx = classDefs[classDefIdx].superclassIdx;
    if (superIdx == kNoIndex) {
        return Ok(jstr::MUtf8StringRef{});
    }
    return typeDescriptor(superIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::sourceFile(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    const ca::u32 fileIdx = classDefs[classDefIdx].sourceFileIdx;
    if (fileIdx == kNoIndex) {
        return Ok(jstr::MUtf8StringRef{});
    }
    return string(fileIdx);
}

Result<TypeListSpan, ReadError> DexFile::typeList(ca::u32 offset)
{
    if (offset == 0) {
        return Ok(TypeListSpan{});
    }
    if (offset >= sourceBytes_.len()) {
        return Err(ReadError::BadTableSpan);
    }

    Result<Reader, ReadError> reader = Reader::at(sourceBytes_, offset);
    if (reader.is_err()) {
        return Err(ReadError::BadTableSpan);
    }
    Reader cur = std::move(reader).unwrap();
    const Result<ca::u32, ReadError> rs = cur.u32();
    if (rs.is_err()) {
        return Err(ReadError::BadTableSpan);
    }
    const ca::u32 count = rs.unwrap();

    const ca::u64 bytes = 4u + static_cast<ca::u64>(count) * 2u;
    if (bytes > static_cast<ca::u64>(sourceBytes_.len() - offset)) {
        return Err(ReadError::BadTableSpan);
    }

    TypeListSpan out;
    out.raw = ByteSpan{offset, static_cast<ca::u32>(bytes)};
    out.size = count;
    out.entries = sourceBytes_.as_ptr() + offset + 4;
    return Ok(out);
}

Result<TypeListSpan, ReadError> DexFile::protoParameters(ca::u32 protoIdx)
{
    if (protoIdx >= protoIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeList(protoIds[protoIdx].parametersOff);
}

Result<TypeListSpan, ReadError> DexFile::interfaces(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeList(classDefs[classDefIdx].interfacesOff);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::fieldClassDescriptor(ca::u32 fieldIdx)
{
    if (fieldIdx >= fieldIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeDescriptor(fieldIds[fieldIdx].classIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::fieldTypeDescriptor(ca::u32 fieldIdx)
{
    if (fieldIdx >= fieldIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeDescriptor(fieldIds[fieldIdx].typeIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::fieldName(ca::u32 fieldIdx)
{
    if (fieldIdx >= fieldIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return string(fieldIds[fieldIdx].nameIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::methodClassDescriptor(ca::u32 methodIdx)
{
    if (methodIdx >= methodIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return typeDescriptor(methodIds[methodIdx].classIdx);
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::methodName(ca::u32 methodIdx)
{
    if (methodIdx >= methodIds.size()) {
        return Err(ReadError::BadIndex);
    }
    return string(methodIds[methodIdx].nameIdx);
}

Result<const ClassData*, ReadError> DexFile::classData(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    if (classDataCache_.size() != classDefs.size()) {
        classDataCache_.resize(classDefs.size());
    }

    LazyClassData& slot = classDataCache_[classDefIdx];
    if (slot.state == LazyClassData::State::Decoded) {
        return Ok(static_cast<const ClassData*>(slot.data.get()));
    }
    if (slot.state == LazyClassData::State::Failed) {
        return Err(slot.error);
    }

    const ca::u32 offset = classDefs[classDefIdx].classDataOff;
    if (offset == 0) {
        slot.state = LazyClassData::State::Decoded;
        return Ok(static_cast<const ClassData*>(nullptr));
    }

    Result<std::unique_ptr<ClassData>, ReadError> decoded = decodeClassData(offset);
    if (decoded.is_err()) {
        slot.state = LazyClassData::State::Failed;
        slot.error = decoded.unwrap_err();
        return Err(slot.error);
    }

    slot.data = std::move(decoded).unwrap();
    slot.state = LazyClassData::State::Decoded;
    return Ok(static_cast<const ClassData*>(slot.data.get()));
}

const ClassData* DexFile::peekClassData(ca::u32 classDefIdx) const noexcept
{
    if (classDefIdx >= classDataCache_.size()) {
        return nullptr;
    }
    const LazyClassData& slot = classDataCache_[classDefIdx];
    return slot.state == LazyClassData::State::Decoded ? slot.data.get() : nullptr;
}

Result<std::unique_ptr<ClassData>, ReadError> DexFile::decodeClassData(ca::u32 offset)
{
    if (offset >= sourceBytes_.len()) {
        return Err(ReadError::BadClassData);
    }

    Result<Reader, ReadError> reader = Reader::at(sourceBytes_, offset);
    if (reader.is_err()) {
        return Err(ReadError::BadClassData);
    }
    Reader cur = std::move(reader).unwrap();

    ca::u32 counts[4] = {0, 0, 0, 0};
    for (ca::u32& count : counts) {
        const Result<ca::u32, ReadError> r = readUleb128(cur);
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
        count = r.unwrap();
    }

    // 条目索引互不重复且必须落在对应 ID 表内，因此计数不可能超过表长。
    // 先做上界闸门，避免畸形计数触发巨量分配。
    const ca::u64 fieldTotal = static_cast<ca::u64>(counts[0]) + counts[1];
    const ca::u64 methodTotal = static_cast<ca::u64>(counts[2]) + counts[3];
    if (fieldTotal > fieldIds.size() || methodTotal > methodIds.size()) {
        return Err(ReadError::BadClassData);
    }

    // 每条 encoded_field 至少 2 字节、encoded_method 至少 3 字节；先按剩余
    // 字节数封顶，避免小文件里伪造大计数触发放大分配。
    const ca::u64 minBytes = static_cast<ca::u64>(counts[0]) * 2u + counts[1] * 2u +
                             static_cast<ca::u64>(counts[2]) * 3u + counts[3] * 3u;
    if (minBytes > cur.remaining()) {
        return Err(ReadError::BadClassData);
    }

    auto data = std::make_unique<ClassData>();

    const auto readFields = [&cur](ca::u32 count, std::vector<EncodedField>& out) -> Result<void, ReadError> {
        out.reserve(count);
        ca::u32 previous = 0;
        for (ca::u32 i = 0; i < count; ++i) {
            const Result<ca::u32, ReadError> rd = readUleb128(cur);
            if (rd.is_err()) {
                return Err(rd.unwrap_err());
            }
            const Result<ca::u32, ReadError> index = nextMemberIndex(rd.unwrap(), previous, i == 0);
            if (index.is_err()) {
                return Err(index.unwrap_err());
            }

            const Result<ca::u32, ReadError> ra = readUleb128(cur);
            if (ra.is_err()) {
                return Err(ra.unwrap_err());
            }

            previous = index.unwrap();
            out.push_back(EncodedField{previous, ra.unwrap()});
        }
        return Ok();
    };

    const auto readMethods = [&cur](ca::u32 count, std::vector<EncodedMethod>& out) -> Result<void, ReadError> {
        out.reserve(count);
        ca::u32 previous = 0;
        for (ca::u32 i = 0; i < count; ++i) {
            const Result<ca::u32, ReadError> rd = readUleb128(cur);
            if (rd.is_err()) {
                return Err(rd.unwrap_err());
            }
            const Result<ca::u32, ReadError> index = nextMemberIndex(rd.unwrap(), previous, i == 0);
            if (index.is_err()) {
                return Err(index.unwrap_err());
            }

            const Result<ca::u32, ReadError> ra = readUleb128(cur);
            if (ra.is_err()) {
                return Err(ra.unwrap_err());
            }
            const Result<ca::u32, ReadError> rc = readUleb128(cur);
            if (rc.is_err()) {
                return Err(rc.unwrap_err());
            }

            previous = index.unwrap();
            out.push_back(EncodedMethod{previous, ra.unwrap(), rc.unwrap()});
        }
        return Ok();
    };

    if (readFields(counts[0], data->staticFields).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readFields(counts[1], data->instanceFields).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readMethods(counts[2], data->directMethods).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readMethods(counts[3], data->virtualMethods).is_err()) {
        return Err(ReadError::BadClassData);
    }

    data->raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(data));
}

Result<const CodeItem*, ReadError> DexFile::codeItem(ca::u32 codeOff)
{
    if (codeOff == 0) {
        return Ok(static_cast<const CodeItem*>(nullptr));
    }

    const auto it = codeCache_.find(codeOff);
    if (it != codeCache_.end()) {
        return Ok(static_cast<const CodeItem*>(it->second.get()));
    }
    const auto failed = codeFailures_.find(codeOff);
    if (failed != codeFailures_.end()) {
        return Err(failed->second);
    }

    Result<std::unique_ptr<CodeItem>, ReadError> decoded = decodeCodeItem(codeOff);
    if (decoded.is_err()) {
        const ReadError error = decoded.unwrap_err();
        codeFailures_.emplace(codeOff, error);
        return Err(error);
    }

    std::unique_ptr<CodeItem> item = std::move(decoded).unwrap();
    const CodeItem* view = item.get();
    codeCache_.emplace(codeOff, std::move(item));
    return Ok(view);
}

const CodeItem* DexFile::peekCodeItem(ca::u32 codeOff) const noexcept
{
    const auto it = codeCache_.find(codeOff);
    return it == codeCache_.end() ? nullptr : it->second.get();
}

Result<std::unique_ptr<CodeItem>, ReadError> DexFile::decodeCodeItem(ca::u32 offset)
{
    Result<CodeItem, ReadError> parsed = parseCodeItem(source(), offset, typeCount(), &diag_);
    if (parsed.is_err()) {
        return Err(parsed.unwrap_err());
    }
    return Ok(std::make_unique<CodeItem>(std::move(parsed).unwrap()));
}

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

}   // namespace dex::core
