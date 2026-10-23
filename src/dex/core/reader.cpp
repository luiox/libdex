/// @file        reader.cpp
/// @brief       DEX 骨架解析（header → map_list → ID 表 → class_defs）。
#include "dex/core/reader.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "dex/core/integrity.hpp"

namespace dex::core {

namespace {

constexpr ca::u32 kHeaderSize = 0x70;
constexpr ca::u32 kHeaderSizeV41 = 0x78;
constexpr ca::u32 kEndianTag = 0x12345678u;

bool isKnownVersion(ca::u16 version) noexcept
{
    switch (version) {
        case 35:
        case 37:
        case 38:
        case 39:
        case 40:
        case 41:
            return true;
        default:
            return false;
    }
}

/// @brief 校验定长表的 (size, off) 并逐条读取。
///
/// size == 0 时允许 off 为任意值（包括 0）；size > 0 而 off 为 0 视为结构损坏。
template <typename Read>
Result<void, ReadError> readFixedTable(const ca::core::Bytes& src,
                                       ca::u32 size,
                                       ca::u32 off,
                                       ca::u32 entrySize,
                                       Read&& read)
{
    if (size == 0) {
        return Ok();
    }
    if (off == 0) {
        return Err(ReadError::BadTableSpan);
    }

    const ca::u64 bytes = static_cast<ca::u64>(size) * entrySize;
    if (off > src.len() || bytes > static_cast<ca::u64>(src.len() - off)) {
        return Err(ReadError::BadTableSpan);
    }

    Result<Reader, ReadError> reader = Reader::at(src, off);
    if (reader.is_err()) {
        return Err(ReadError::BadTableSpan);
    }
    Reader cur = std::move(reader).unwrap();
    for (ca::u32 i = 0; i < size; ++i) {
        const Result<void, ReadError> r = read(cur);
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }
    return Ok();
}

/// @brief 在任意偏移读一个小端 u32（endian_tag 检查等点读用）。
Result<ca::u32, ReadError> u32At(const ca::core::Bytes& source, ca::usize offset)
{
    Result<Reader, ReadError> reader = Reader::at(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();
    return cur.u32();
}

}   // namespace

Result<std::unique_ptr<DexFile>, ReadError> readDex(ByteSlice bytes, const ReadOptions& opt)
{
    // 源字节只在这里决定一次所有权形态：默认复制进 libca Bytes，关闭保留时
    // 用 from_static 借用调用方 buffer。后续所有解析都走共享存储的切片。
    ca::core::Bytes source = opt.preserveSourceBytes
                                 ? ca::core::Bytes::copy_from_slice(bytes.data(), bytes.size())
                                 : ca::core::Bytes::from_static(bytes.data(), bytes.size());
    Result<Reader, ReadError> reader = Reader::at(source, 0);
    if (reader.is_err()) {
        return Err(ReadError::Truncated);
    }
    Reader cur = std::move(reader).unwrap();

    // ---- magic 与版本 ----
    const Result<ByteSlice, ReadError> rmagic = cur.take(8);
    if (rmagic.is_err()) {
        return Err(rmagic.unwrap_err());
    }
    const ByteSlice magic = rmagic.unwrap();
    if (magic[0] != 'd' || magic[1] != 'e' || magic[2] != 'x' || magic[3] != '\n' ||
        magic[7] != 0) {
        return Err(ReadError::BadMagic);
    }
    for (ca::u32 i = 4; i < 7; ++i) {
        if (magic[i] < '0' || magic[i] > '9') {
            return Err(ReadError::BadMagic);
        }
    }
    const ca::u16 version = static_cast<ca::u16>((magic[4] - '0') * 100 +
                                                 (magic[5] - '0') * 10 +
                                                 (magic[6] - '0'));
    if (!isKnownVersion(version)) {
        return Err(ReadError::UnsupportedVersion);
    }

    Diagnostics diag;
    if (version > opt.maxSupportedVersion) {
        diag.warn(ReadError::UnsupportedVersion, 4);
    }

    // ---- 头部固定区 ----
    const Result<ca::u32, ReadError> rchecksum = cur.u32();
    const Result<ByteSlice, ReadError> rsignature = cur.take(20);
    if (rchecksum.is_err() || rsignature.is_err()) {
        return Err(ReadError::Truncated);
    }

    // 小端标签先于其余字段核对：大端变体的后续字段全部是字节反转的，
    // 继续解析只会产出垃圾诊断。
    const Result<ca::u32, ReadError> reindian = u32At(source, 40);
    if (reindian.is_err()) {
        return Err(ReadError::Truncated);
    }
    if (reindian.unwrap() != kEndianTag) {
        return Err(ReadError::BadEndianTag);
    }

    DexHeader header;
    header.version = version;
    header.checksum = rchecksum.unwrap();
    std::memcpy(header.signature.data(), rsignature.unwrap().data(), header.signature.size());

    ca::u32* const fields[] = {
        &header.fileSize,      &header.headerSize,     &header.endianTag,
        &header.linkSize,      &header.linkOff,        &header.mapOff,
        &header.stringIdsSize, &header.stringIdsOff,   &header.typeIdsSize,
        &header.typeIdsOff,    &header.protoIdsSize,   &header.protoIdsOff,
        &header.fieldIdsSize,  &header.fieldIdsOff,    &header.methodIdsSize,
        &header.methodIdsOff,  &header.classDefsSize,  &header.classDefsOff,
        &header.dataSize,      &header.dataOff,
    };
    for (ca::u32* field : fields) {
        const Result<ca::u32, ReadError> r = cur.u32();
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
        *field = r.unwrap();
    }

    if (header.headerSize < kHeaderSize) {
        return Err(ReadError::BadHeaderSize);
    }
    const ca::u32 expectedHeaderSize = version >= 41 ? kHeaderSizeV41 : kHeaderSize;
    if (header.headerSize != expectedHeaderSize) {
        diag.warn(ReadError::BadHeaderSize, 36);
    }

    if (version >= 41 && header.headerSize >= kHeaderSizeV41) {
        const Result<ca::u32, ReadError> rcontainer = cur.u32();
        const Result<ca::u32, ReadError> rhoffset = cur.u32();
        if (rcontainer.is_err() || rhoffset.is_err()) {
            return Err(ReadError::Truncated);
        }
        header.containerSize = rcontainer.unwrap();
        header.headerOffset = rhoffset.unwrap();
    }

    if (header.fileSize != bytes.size()) {
        diag.warn(ReadError::BadFileSize, 32);
    }
    if (header.linkSize != 0) {
        const ca::u64 linkEnd = static_cast<ca::u64>(header.linkOff) + header.linkSize;
        if (header.linkOff > bytes.size() || linkEnd > bytes.size()) {
            diag.warn(ReadError::BadTableSpan, 44);
        }
    }
    if (header.dataSize != 0) {
        const ca::u64 dataEnd = static_cast<ca::u64>(header.dataOff) + header.dataSize;
        if (header.dataOff > bytes.size() || dataEnd > bytes.size()) {
            diag.warn(ReadError::BadTableSpan, 104);
        }
    }

    // ---- 校验字段 ----
    if (opt.verifyIntegrity) {
        // 尾部多余字节不属于 dex 内容；按 header.file_size 截断后核对。
        const ca::usize coveredSize =
            header.fileSize <= bytes.size() ? header.fileSize : bytes.size();
        const Integrity integrity =
            verifyIntegrity(subOrEmpty(bytes, 0, coveredSize), header.checksum, header.signature);
        if (!integrity.checksumOk) {
            diag.warn(ReadError::BadChecksum, 8);
        }
        if (!integrity.signatureOk) {
            diag.warn(ReadError::BadSignature, 12);
        }
    }

    // ---- 交入源字节，后续解析一律基于模型持有的共享存储 ----
    auto file = std::make_unique<DexFile>();
    file->header = header;
    file->adoptSource(std::move(source));
    const ca::core::Bytes& src = file->sourceBytes();

    // ---- map_list ----
    if (header.mapOff == 0) {
        diag.warn(ReadError::BadMapList, 52);
    } else if (header.mapOff > src.len() || src.len() - header.mapOff < 4) {
        diag.warn(ReadError::BadMapList, 52);
    } else {
        Result<Reader, ReadError> mapReader = Reader::at(src, header.mapOff);
        if (mapReader.is_err()) {
            diag.warn(ReadError::BadMapList, 52);
        } else {
            Reader mapCur = std::move(mapReader).unwrap();
            const Result<ca::u32, ReadError> rcount = mapCur.u32();
            const ca::u32 count = rcount.is_err() ? 0 : rcount.unwrap();
            const ca::u64 bytesNeeded = 4u + static_cast<ca::u64>(count) * 12u;
            if (rcount.is_err() ||
                bytesNeeded > static_cast<ca::u64>(src.len() - header.mapOff)) {
                diag.warn(ReadError::BadMapList, header.mapOff);
            } else {
                file->mapItems.reserve(count);
                ca::u32 previousOffset = 0;
                for (ca::u32 i = 0; i < count; ++i) {
                    const Result<ca::u16, ReadError> rtype = mapCur.u16();
                    const Result<ca::u16, ReadError> runused = mapCur.u16();
                    const Result<ca::u32, ReadError> rsize = mapCur.u32();
                    const Result<ca::u32, ReadError> roff = mapCur.u32();
                    if (rtype.is_err() || runused.is_err() || rsize.is_err() || roff.is_err()) {
                        diag.warn(ReadError::BadMapList, header.mapOff);
                        break;
                    }

                    MapItem item;
                    item.type = static_cast<MapType>(rtype.unwrap());
                    item.unused = runused.unwrap();
                    item.size = rsize.unwrap();
                    item.offset = roff.unwrap();

                    if (i > 0 && item.offset < previousOffset) {
                        diag.warn(ReadError::BadMapList, header.mapOff);
                    }
                    if (item.size != 0 && item.offset >= src.len()) {
                        diag.warn(ReadError::BadIndex, header.mapOff);
                    }
                    previousOffset = item.offset;
                    file->mapItems.push_back(item);
                }
            }
        }
    }

    // ---- 未建模 section 的原始区间（未知类型不丢弃） ----
    {
        struct Ordered
        {
            ca::u32 offset = 0;
            ca::u32 index = 0;
        };
        std::vector<Ordered> ordered;
        ordered.reserve(file->mapItems.size());
        for (ca::u32 i = 0; i < file->mapItems.size(); ++i) {
            ordered.push_back(Ordered{file->mapItems[i].offset, i});
        }
        std::sort(ordered.begin(), ordered.end(),
                  [](const Ordered& a, const Ordered& b) { return a.offset < b.offset; });

        const ca::u32 fileEnd = header.fileSize <= src.len()
                                    ? header.fileSize
                                    : static_cast<ca::u32>(src.len());
        for (ca::usize k = 0; k < ordered.size(); ++k) {
            const MapItem& item = file->mapItems[ordered[k].index];
            if (isModeledMapType(item.type) || item.offset > src.len()) {
                continue;
            }
            ca::u32 end = (k + 1 < ordered.size()) ? ordered[k + 1].offset : fileEnd;
            if (end < item.offset) {
                end = item.offset;
            }
            if (end > src.len()) {
                end = static_cast<ca::u32>(src.len());
            }
            file->rawSections.push_back(RawSection{
                static_cast<ca::u16>(item.type), item.size,
                ByteSpan{item.offset, end - item.offset}});
        }
    }

    // ---- 五张 ID 表 + class_defs（定长条目，eager）----

    const ca::u32 stringCount = header.stringIdsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, stringCount, header.stringIdsOff, 4,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u32, ReadError> v = c.u32();
                if (v.is_err()) {
                    return Err(v.unwrap_err());
                }
                file->stringIds.push_back(StringId{v.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    const ca::u32 typeCount = header.typeIdsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, typeCount, header.typeIdsOff, 4,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u32, ReadError> v = c.u32();
                if (v.is_err()) {
                    return Err(v.unwrap_err());
                }
                file->typeIds.push_back(TypeId{v.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    const ca::u32 protoCount = header.protoIdsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, protoCount, header.protoIdsOff, 12,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u32, ReadError> a = c.u32();
                const Result<ca::u32, ReadError> b = c.u32();
                const Result<ca::u32, ReadError> d = c.u32();
                if (a.is_err() || b.is_err() || d.is_err()) {
                    return Err(ReadError::Truncated);
                }
                file->protoIds.push_back(ProtoId{a.unwrap(), b.unwrap(), d.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    const ca::u32 fieldCount = header.fieldIdsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, fieldCount, header.fieldIdsOff, 8,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u16, ReadError> classIdx = c.u16();
                const Result<ca::u16, ReadError> typeIdx = c.u16();
                const Result<ca::u32, ReadError> nameIdx = c.u32();
                if (classIdx.is_err() || typeIdx.is_err() || nameIdx.is_err()) {
                    return Err(ReadError::Truncated);
                }
                file->fieldIds.push_back(
                    FieldId{classIdx.unwrap(), typeIdx.unwrap(), nameIdx.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    const ca::u32 methodCount = header.methodIdsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, methodCount, header.methodIdsOff, 8,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u16, ReadError> classIdx = c.u16();
                const Result<ca::u16, ReadError> protoIdx = c.u16();
                const Result<ca::u32, ReadError> nameIdx = c.u32();
                if (classIdx.is_err() || protoIdx.is_err() || nameIdx.is_err()) {
                    return Err(ReadError::Truncated);
                }
                file->methodIds.push_back(
                    MethodId{classIdx.unwrap(), protoIdx.unwrap(), nameIdx.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    const ca::u32 classDefCount = header.classDefsSize;
    {
        const Result<void, ReadError> r = readFixedTable(
            src, classDefCount, header.classDefsOff, 32,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u32, ReadError> classIdx = c.u32();
                const Result<ca::u32, ReadError> access = c.u32();
                const Result<ca::u32, ReadError> superIdx = c.u32();
                const Result<ca::u32, ReadError> interfacesOff = c.u32();
                const Result<ca::u32, ReadError> sourceFileIdx = c.u32();
                const Result<ca::u32, ReadError> annotationsOff = c.u32();
                const Result<ca::u32, ReadError> classDataOff = c.u32();
                const Result<ca::u32, ReadError> staticValuesOff = c.u32();
                if (classIdx.is_err() || access.is_err() || superIdx.is_err() ||
                    interfacesOff.is_err() || sourceFileIdx.is_err() ||
                    annotationsOff.is_err() || classDataOff.is_err() ||
                    staticValuesOff.is_err()) {
                    return Err(ReadError::Truncated);
                }
                file->classDefs.push_back(ClassDef{
                    classIdx.unwrap(),      access.unwrap(),        superIdx.unwrap(),
                    interfacesOff.unwrap(), sourceFileIdx.unwrap(), annotationsOff.unwrap(),
                    classDataOff.unwrap(),  staticValuesOff.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    // ---- call_site_id 与 method_handle：没有头部计数，只由 map_list 定位 ----
    if (const MapItem* item = file->findMapItem(MapType::CallSiteIdItem);
        item != nullptr && item->size != 0) {
        const Result<void, ReadError> r = readFixedTable(
            src, item->size, item->offset, 4,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u32, ReadError> off = c.u32();
                if (off.is_err()) {
                    return Err(off.unwrap_err());
                }
                file->callSites.push_back(CallSiteId{off.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    if (const MapItem* item = file->findMapItem(MapType::MethodHandleItem);
        item != nullptr && item->size != 0) {
        const Result<void, ReadError> r = readFixedTable(
            src, item->size, item->offset, 8,
            [&file](Reader& c) -> Result<void, ReadError> {
                const Result<ca::u16, ReadError> handleType = c.u16();
                const Result<ca::u16, ReadError> unused1 = c.u16();
                const Result<ca::u16, ReadError> targetIdx = c.u16();
                const Result<ca::u16, ReadError> unused2 = c.u16();
                if (handleType.is_err() || unused1.is_err() || targetIdx.is_err() ||
                    unused2.is_err()) {
                    return Err(ReadError::Truncated);
                }
                file->methodHandles.push_back(MethodHandle{
                    handleType.unwrap(), unused1.unwrap(), targetIdx.unwrap(),
                    unused2.unwrap()});
                return Ok();
            });
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    // ---- 语义校验：悬垂索引只降级，不拒绝 ----
    const ca::u32 actualStringCount = file->stringCount();
    const ca::u32 actualTypeCount = file->typeCount();
    const ca::u32 actualProtoCount = file->protoCount();

    for (ca::u32 i = 0; i < actualStringCount; ++i) {
        if (file->stringIds[i].dataOff >= src.len()) {
            diag.warn(ReadError::BadIndex, header.stringIdsOff + i * 4u);
        }
    }
    for (ca::u32 i = 0; i < actualTypeCount; ++i) {
        if (file->typeIds[i].descriptorIdx >= actualStringCount) {
            diag.warn(ReadError::BadIndex, header.typeIdsOff + i * 4u);
        }
    }
    for (ca::u32 i = 0; i < actualProtoCount; ++i) {
        const ProtoId& proto = file->protoIds[i];
        const ca::u32 offset = header.protoIdsOff + i * 12u;
        if (proto.shortyIdx >= actualStringCount || proto.returnTypeIdx >= actualTypeCount ||
            (proto.parametersOff != 0 && proto.parametersOff >= src.len())) {
            diag.warn(ReadError::BadIndex, offset);
        }
    }
    for (ca::u32 i = 0; i < file->fieldCount(); ++i) {
        const FieldId& field = file->fieldIds[i];
        if (field.classIdx >= actualTypeCount || field.typeIdx >= actualTypeCount ||
            field.nameIdx >= actualStringCount) {
            diag.warn(ReadError::BadIndex, header.fieldIdsOff + i * 8u);
        }
    }
    for (ca::u32 i = 0; i < file->methodCount(); ++i) {
        const MethodId& method = file->methodIds[i];
        if (method.classIdx >= actualTypeCount || method.protoIdx >= actualProtoCount ||
            method.nameIdx >= actualStringCount) {
            diag.warn(ReadError::BadIndex, header.methodIdsOff + i * 8u);
        }
    }
    for (ca::u32 i = 0; i < file->classCount(); ++i) {
        const ClassDef& def = file->classDefs[i];
        const ca::u32 offset = header.classDefsOff + i * 32u;
        const bool badRef = def.classIdx >= actualTypeCount ||
                            (def.superclassIdx != DexFile::kNoIndex &&
                             def.superclassIdx >= actualTypeCount) ||
                            (def.sourceFileIdx != DexFile::kNoIndex &&
                             def.sourceFileIdx >= actualStringCount) ||
                            (def.interfacesOff != 0 && def.interfacesOff >= src.len()) ||
                            (def.annotationsOff != 0 && def.annotationsOff >= src.len()) ||
                            (def.classDataOff != 0 && def.classDataOff >= src.len()) ||
                            (def.staticValuesOff != 0 && def.staticValuesOff >= src.len());
        if (badRef) {
            diag.warn(ReadError::BadIndex, offset);
        }
    }

    if (const MapItem* item = file->findMapItem(MapType::CallSiteIdItem)) {
        for (ca::u32 i = 0; i < file->callSiteCount(); ++i) {
            const ca::u32 off = file->callSites[i].callSiteOff;
            if (off == 0 || off >= src.len()) {
                diag.warn(ReadError::BadIndex, item->offset + i * 4u);
            }
        }
    }
    if (const MapItem* item = file->findMapItem(MapType::MethodHandleItem)) {
        for (ca::u32 i = 0; i < file->methodHandleCount(); ++i) {
            const MethodHandle& handle = file->methodHandles[i];
            bool badRef = handle.handleType > 8;
            if (!badRef) {
                badRef = handle.handleType <= 3
                             ? handle.targetIdx >= file->fieldCount()
                             : handle.targetIdx >= file->methodCount();
            }
            if (badRef) {
                diag.warn(ReadError::BadIndex, item->offset + i * 8u);
            }
        }
    }

    // ---- map 计数与头部表计数交叉核对 ----
    const struct
    {
        MapType type;
        ca::u32 count;
    } expectedCounts[] = {
        {MapType::StringIdItem, file->stringCount()},
        {MapType::TypeIdItem, file->typeCount()},
        {MapType::ProtoIdItem, file->protoCount()},
        {MapType::FieldIdItem, file->fieldCount()},
        {MapType::MethodIdItem, file->methodCount()},
        {MapType::ClassDefItem, file->classCount()},
    };
    for (const auto& expected : expectedCounts) {
        const MapItem* item = file->findMapItem(expected.type);
        if (item != nullptr && item->size != expected.count) {
            diag.warn(ReadError::BadMapList, item->offset);
        }
    }

    file->diagnostics() = std::move(diag);
    file->setState(file->diagnostics().empty() ? ParseState::Validated
                                               : ParseState::Recovered);
    return Ok(std::move(file));
}

}   // namespace dex::core
