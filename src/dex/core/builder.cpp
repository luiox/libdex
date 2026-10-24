/// @file        builder.cpp
/// @brief       canonical 布局重建与偏移回填。
#include "dex/core/builder.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "jstr/conversion.hpp"

#include "dex/core/annotation.hpp"
#include "dex/core/debug_info.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/integrity.hpp"
#include "dex/core/leb128.hpp"

namespace dex::core {

namespace {

constexpr ca::u32 kHeaderSize = 0x70;
constexpr ca::u32 kEndianTag = 0x12345678u;

ca::u32 alignUp(ca::u32 value, ca::u32 alignment) noexcept
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

ca::u32 offsetOf(const std::vector<ca::u8>& out) noexcept
{
    return static_cast<ca::u32>(out.size());
}

void alignOut(std::vector<ca::u8>& out, ca::u32 alignment)
{
    out.resize(alignUp(offsetOf(out), alignment), 0);
}

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

void putU32(std::vector<ca::u8>& out, ca::u32 offset, ca::u32 value)
{
    out[offset] = static_cast<ca::u8>(value & 0xFFu);
    out[offset + 1] = static_cast<ca::u8>((value >> 8) & 0xFFu);
    out[offset + 2] = static_cast<ca::u8>((value >> 16) & 0xFFu);
    out[offset + 3] = static_cast<ca::u8>(value >> 24);
}

template <typename T>
Result<const T*, WriteError> requireDecoded(Result<const T*, ReadError> result)
{
    if (result.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    const T* item = result.unwrap();
    if (item == nullptr) {
        return Err(WriteError::InvalidModel);
    }
    return Ok(item);
}

/// @brief 源条目副本：按旧偏移去重，记录新偏移。
struct ItemTable
{
    std::vector<std::vector<ca::u8>> items;
    std::vector<ca::u32> newOffsets;
    std::unordered_map<ca::u32, ca::usize> indexByOld;

    bool contains(ca::u32 oldOff) const { return indexByOld.count(oldOff) != 0; }

    ca::usize add(ca::u32 oldOff, std::vector<ca::u8> bytes)
    {
        const auto it = indexByOld.find(oldOff);
        if (it != indexByOld.end()) {
            return it->second;
        }
        const ca::usize index = items.size();
        indexByOld.emplace(oldOff, index);
        items.push_back(std::move(bytes));
        newOffsets.push_back(0);
        return index;
    }

    bool lookup(ca::u32 oldOff, ca::u32* newOff) const
    {
        const auto it = indexByOld.find(oldOff);
        if (it == indexByOld.end()) {
            return false;
        }
        *newOff = newOffsets[it->second];
        return true;
    }
};

struct MethodSite
{
    ca::u32 methodIdx = 0;
    ca::u32 codeOff = 0;
};

/// @brief 一个待布局的 code_item；共享同一旧 code_off 的方法归入同一个 unit。
struct CodeUnit
{
    const CodeItem* item = nullptr;
    ByteSlice insns{};
    std::vector<ca::u8> remappedInsns;  ///< 非空时 insns 指向这里
    ca::u32 oldDebugOff = 0;
    ca::u32 sortKey = 0;                ///< 新 method 索引，决定 code_item 布局顺序
    std::vector<ca::u32> methods;       ///< 复用该 code_item 的旧 method 索引
    ca::u32 newOffset = 0;
};

/// @brief 重建前的 ID 表护栏：容量与表内索引。
///
/// DEX 的 type/proto/field/method 索引是 16 位；string 索引是 32 位。
/// 这里只检查模型自洽，不检查排序（排序是 DEX 规范要求，reader 只做诊断）。
bool validIdTables(const DexFile& dex) noexcept
{
    if (dex.stringIds.size() > 0xFFFFFFFFu ||
        dex.typeIds.size() > DexFile::kIdTableLimit ||
        dex.protoIds.size() > DexFile::kIdTableLimit ||
        dex.fieldIds.size() > DexFile::kIdTableLimit ||
        dex.methodIds.size() > DexFile::kIdTableLimit) {
        return false;
    }

    const ca::u32 stringCount = dex.stringCount();
    const ca::u32 typeCount = dex.typeCount();
    const ca::u32 protoCount = dex.protoCount();
    const ca::u32 fieldCount = dex.fieldCount();
    const ca::u32 methodCount = dex.methodCount();

    for (const TypeId& type : dex.typeIds) {
        if (type.descriptorIdx >= stringCount) {
            return false;
        }
    }
    for (const ProtoId& proto : dex.protoIds) {
        if (proto.shortyIdx >= stringCount || proto.returnTypeIdx >= typeCount) {
            return false;
        }
    }
    for (const FieldId& field : dex.fieldIds) {
        if (field.classIdx >= typeCount || field.typeIdx >= typeCount ||
            field.nameIdx >= stringCount) {
            return false;
        }
    }
    for (const MethodId& method : dex.methodIds) {
        if (method.classIdx >= typeCount || method.protoIdx >= protoCount ||
            method.nameIdx >= stringCount) {
            return false;
        }
    }
    for (const ClassDef& def : dex.classDefs) {
        if (def.classIdx >= typeCount ||
            (def.superclassIdx != DexFile::kNoIndex && def.superclassIdx >= typeCount) ||
            (def.sourceFileIdx != DexFile::kNoIndex && def.sourceFileIdx >= stringCount)) {
            return false;
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        if (site.callSiteOff == 0) {
            return false;
        }
    }
    for (const MethodHandle& handle : dex.methodHandles) {
        if (handle.handleType > 8) {
            return false;
        }
        const ca::u32 limit = handle.handleType <= 3 ? fieldCount : methodCount;
        if (handle.targetIdx >= limit) {
            return false;
        }
    }
    return true;
}

struct PoolString
{
    std::u16string key;        ///< UTF-16 code unit 序列，DEX 排序键
    std::vector<ca::u8> data;  ///< 原始 string_data_item 编码
    ca::u32 oldIndex = 0;
};

/// @brief canonical 字符串池与旧索引到新索引的映射。
struct StringPool
{
    std::vector<PoolString> strings;   ///< 按 UTF-16 升序、已去重
    std::vector<ca::u32> remap;        ///< old string_idx → new string_idx
    std::vector<ca::u32> poolIndexByOld;
    bool remapIsIdentity = true;       ///< 所有旧索引是否原地不动

    const std::u16string& keyOf(ca::u32 oldIndex) const
    {
        return strings[poolIndexByOld[oldIndex]].key;
    }
};

/// @brief 一张可重排 ID 表的旧→新索引映射。
struct IdOrder
{
    std::vector<ca::u32> oldIndexByNew;  ///< 新下标 → 旧索引
    std::vector<ca::u32> remap;          ///< 旧索引 → 新下标
    bool identity = true;
};

/// @brief 按旧索引比较的排序器，返回 a 是否严格小于 b。
template <typename Less>
Result<IdOrder, WriteError> makeIdOrder(ca::u32 count, Less less)
{
    IdOrder order;
    order.oldIndexByNew.resize(count);
    order.remap.resize(count);
    for (ca::u32 i = 0; i < count; ++i) {
        order.oldIndexByNew[i] = i;
    }

    std::sort(order.oldIndexByNew.begin(), order.oldIndexByNew.end(),
              [&less](ca::u32 a, ca::u32 b) {
                  if (less(a, b)) {
                      return true;
                  }
                  if (less(b, a)) {
                      return false;
                  }
                  return a < b;
              });

    for (ca::u32 newIndex = 0; newIndex < count; ++newIndex) {
        const ca::u32 oldIndex = order.oldIndexByNew[newIndex];
        if (newIndex != 0) {
            const ca::u32 previous = order.oldIndexByNew[newIndex - 1];
            if (!less(previous, oldIndex)) {
                return Err(WriteError::InvalidModel);  // 键重复
            }
        }
        order.remap[oldIndex] = newIndex;
        if (oldIndex != newIndex) {
            order.identity = false;
        }
    }
    return Ok(std::move(order));
}

/// @brief 从 string_data_item 字节解出 UTF-16 排序键，并校验声明的长度。
Result<std::u16string, WriteError> decodeStringKey(const std::vector<ca::u8>& item)
{
    const ca::core::Bytes bytes = ca::core::Bytes::from_static(item.data(), item.size());
    Result<Reader, ReadError> reader = Reader::at(bytes, 0);
    if (reader.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    Reader cur = std::move(reader).unwrap();
    const Result<ca::u32, ReadError> declared = readUleb128(cur);
    if (declared.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    const ca::usize start = cur.pos();
    if (start >= item.size() || item.back() != 0) {
        return Err(WriteError::SourceUnreadable);
    }

    const ca::usize bodySize = item.size() - start - 1;
    Result<std::u16string, jstr::EncodingError> key = jstr::mutf8_to_utf16(
        jstr::MUtf8StringRef(reinterpret_cast<const char*>(item.data() + start), bodySize));
    if (key.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    std::u16string units = std::move(key).unwrap();
    if (units.size() != declared.unwrap()) {
        return Err(WriteError::SourceUnreadable);
    }
    return Ok(std::move(units));
}

Result<StringPool, WriteError> collectStringPool(DexFile& dex)
{
    const ca::u32 count = dex.stringCount();
    StringPool pool;
    pool.remap.resize(count);
    pool.poolIndexByOld.resize(count);

    std::vector<PoolString> entries;
    entries.reserve(count);
    for (ca::u32 i = 0; i < count; ++i) {
        Result<std::vector<ca::u8>, ReadError> fetched = dex.stringData(i);
        if (fetched.is_err()) {
            return Err(fetched.unwrap_err() == ReadError::BadIndex
                           ? WriteError::InvalidModel
                           : WriteError::SourceUnreadable);
        }
        std::vector<ca::u8> data = std::move(fetched).unwrap();
        Result<std::u16string, WriteError> key = decodeStringKey(data);
        if (key.is_err()) {
            return Err(key.unwrap_err());
        }
        entries.push_back(PoolString{std::move(key).unwrap(), std::move(data), i});
    }

    std::sort(entries.begin(), entries.end(), [](const PoolString& a, const PoolString& b) {
        if (a.key != b.key) {
            return a.key < b.key;
        }
        return a.oldIndex < b.oldIndex;
    });

    for (PoolString& entry : entries) {
        const ca::u32 oldIndex = entry.oldIndex;
        ca::u32 canonical = 0;
        if (pool.strings.empty() || pool.strings.back().key != entry.key) {
            canonical = static_cast<ca::u32>(pool.strings.size());
            pool.strings.push_back(std::move(entry));
        } else {
            canonical = static_cast<ca::u32>(pool.strings.size() - 1);
        }
        pool.remap[oldIndex] = canonical;
        pool.poolIndexByOld[oldIndex] = canonical;
    }

    for (ca::u32 i = 0; i < count; ++i) {
        if (pool.remap[i] != i) {
            pool.remapIsIdentity = false;
            break;
        }
    }
    return Ok(std::move(pool));
}

/// @brief 重建期间有效的索引映射；call_site/method_handle 不重排。
struct IndexRemap
{
    const std::vector<ca::u32>& strings;
    const std::vector<ca::u32>& types;
    const std::vector<ca::u32>& protos;
    const std::vector<ca::u32>& fields;
    const std::vector<ca::u32>& methods;
};

Result<std::vector<ca::u8>, WriteError> remapInsnIndices(ByteSlice insns,
                                                         const IndexRemap& maps)
{
    Result<std::vector<Insn>, InsnError> decoded = decodeInsns(insns);
    if (decoded.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    std::vector<Insn> list = std::move(decoded).unwrap();

    bool changed = false;
    for (Insn& insn : list) {
        const std::vector<ca::u32>* table = nullptr;
        switch (insn.indexKind) {
            case IndexKind::String:
                table = &maps.strings;
                break;
            case IndexKind::Type:
                table = &maps.types;
                break;
            case IndexKind::Proto:
                table = &maps.protos;
                break;
            case IndexKind::Field:
                table = &maps.fields;
                break;
            case IndexKind::Method:
                table = &maps.methods;
                break;
            default:
                break;
        }
        if (table != nullptr) {
            if (insn.index >= table->size()) {
                return Err(WriteError::InvalidModel);
            }
            const ca::u32 mapped = (*table)[insn.index];
            if (mapped != insn.index) {
                insn.index = mapped;
                changed = true;
            }
        }
        if (insn.hasProtoIndex) {
            if (insn.protoIndex >= maps.protos.size()) {
                return Err(WriteError::InvalidModel);
            }
            const ca::u32 mapped = maps.protos[insn.protoIndex];
            if (mapped != insn.protoIndex) {
                insn.protoIndex = mapped;
                changed = true;
            }
        }
    }
    if (!changed) {
        std::vector<ca::u8> raw;
        if (!insns.empty()) {
            raw.assign(insns.data(), insns.data() + insns.size());
        }
        return Ok(std::move(raw));
    }

    Result<std::vector<ca::u8>, InsnEncodeError> encoded = encodeInsns(list);
    if (encoded.is_err()) {
        return Err(encoded.unwrap_err() == InsnEncodeError::OperandOverflow
                       ? WriteError::Unencodable
                       : WriteError::SourceUnreadable);
    }
    return Ok(std::move(encoded).unwrap());
}

Result<void, WriteError> remapDebugInfoIndices(DebugInfo& info, const IndexRemap& maps)
{
    bool headerChanged = false;
    for (ca::u32& name : info.parameterNames) {
        if (name >= maps.strings.size()) {
            return Err(WriteError::InvalidModel);
        }
        const ca::u32 mapped = maps.strings[name];
        if (mapped != name) {
            name = mapped;
            headerChanged = true;
        }
    }
    if (headerChanged) {
        info.headerRaw = ByteSlice{};
    }

    for (DebugOp& op : info.ops) {
        bool changed = false;
        if (op.opcode == kDbgStartLocal || op.opcode == kDbgStartLocalExtended ||
            op.opcode == kDbgSetFile) {
            if (op.nameIdx >= maps.strings.size()) {
                return Err(WriteError::InvalidModel);
            }
            const ca::u32 mapped = maps.strings[op.nameIdx];
            if (mapped != op.nameIdx) {
                op.nameIdx = mapped;
                changed = true;
            }
        }
        if (op.opcode == kDbgStartLocal || op.opcode == kDbgStartLocalExtended) {
            if (op.typeIdx >= maps.types.size()) {
                return Err(WriteError::InvalidModel);
            }
            const ca::u32 mapped = maps.types[op.typeIdx];
            if (mapped != op.typeIdx) {
                op.typeIdx = mapped;
                changed = true;
            }
        }
        if (op.opcode == kDbgStartLocalExtended) {
            if (op.sigIdx >= maps.strings.size()) {
                return Err(WriteError::InvalidModel);
            }
            const ca::u32 mapped = maps.strings[op.sigIdx];
            if (mapped != op.sigIdx) {
                op.sigIdx = mapped;
                changed = true;
            }
        }
        if (changed) {
            op.raw = ByteSlice{};
        }
    }
    return Ok();
}

ca::u8 minimalIndexWidth(ca::u32 value) noexcept
{
    if (value <= 0xFFu) {
        return 1;
    }
    if (value <= 0xFFFFu) {
        return 2;
    }
    if (value <= 0xFFFFFFu) {
        return 3;
    }
    return 4;
}

Result<void, WriteError> remapValueIndex(EncodedValue& value,
                                         const std::vector<ca::u32>& remap)
{
    if (value.index >= remap.size()) {
        return Err(WriteError::InvalidModel);
    }
    const ca::u32 mapped = remap[value.index];
    if (mapped == value.index) {
        return Ok();
    }
    value.index = mapped;
    // 新索引可能比原宽度更长；只增不减，保留源编码的宽裕宽度。
    const ca::u8 width = minimalIndexWidth(mapped);
    if (static_cast<ca::u32>(value.valueArg) + 1u < width) {
        value.valueArg = static_cast<ca::u8>(width - 1u);
    }
    return Ok();
}

Result<void, WriteError> remapValueIndices(EncodedValue& value, const IndexRemap& maps)
{
    switch (value.type) {
        case EncodedValueType::String:
            return remapValueIndex(value, maps.strings);
        case EncodedValueType::Type:
            return remapValueIndex(value, maps.types);
        case EncodedValueType::MethodType:
            return remapValueIndex(value, maps.protos);
        case EncodedValueType::Field:
        case EncodedValueType::Enum:
            return remapValueIndex(value, maps.fields);
        case EncodedValueType::Method:
            return remapValueIndex(value, maps.methods);
        case EncodedValueType::Array:
            for (EncodedValue& element : value.array) {
                const Result<void, WriteError> mapped = remapValueIndices(element, maps);
                if (mapped.is_err()) {
                    return Err(mapped.unwrap_err());
                }
            }
            return Ok();
        case EncodedValueType::Annotation:
            if (value.annotation != nullptr) {
                if (value.annotation->typeIdx >= maps.types.size()) {
                    return Err(WriteError::InvalidModel);
                }
                value.annotation->typeIdx = maps.types[value.annotation->typeIdx];
                for (AnnotationElement& element : value.annotation->elements) {
                    if (element.nameIdx >= maps.strings.size()) {
                        return Err(WriteError::InvalidModel);
                    }
                    element.nameIdx = maps.strings[element.nameIdx];
                    const Result<void, WriteError> mapped =
                        remapValueIndices(element.value, maps);
                    if (mapped.is_err()) {
                        return Err(mapped.unwrap_err());
                    }
                }
            }
            return Ok();
        default:
            return Ok();
    }
}

Result<std::vector<ca::u8>, WriteError> encodeAnnotationItemRemapped(
    const AnnotationItem& item, const IndexRemap& maps)
{
    AnnotationItem copy = item;
    if (copy.annotation.typeIdx >= maps.types.size()) {
        return Err(WriteError::InvalidModel);
    }
    copy.annotation.typeIdx = maps.types[copy.annotation.typeIdx];
    for (AnnotationElement& element : copy.annotation.elements) {
        if (element.nameIdx >= maps.strings.size()) {
            return Err(WriteError::InvalidModel);
        }
        element.nameIdx = maps.strings[element.nameIdx];
        const Result<void, WriteError> mapped = remapValueIndices(element.value, maps);
        if (mapped.is_err()) {
            return Err(mapped.unwrap_err());
        }
    }
    return writeAnnotationItem(copy);
}

Result<std::vector<ca::u8>, WriteError> encodeArrayRemapped(const EncodedArrayItem& item,
                                                            const IndexRemap& maps)
{
    EncodedArrayItem copy = item;
    for (EncodedValue& value : copy.values) {
        const Result<void, WriteError> mapped = remapValueIndices(value, maps);
        if (mapped.is_err()) {
            return Err(mapped.unwrap_err());
        }
    }
    return writeEncodedArrayItem(copy);
}

Result<std::vector<AnnotationsDirectoryEntry>, WriteError> remapDirectoryEntries(
    const std::vector<AnnotationsDirectoryEntry>& entries,
    const std::vector<ca::u32>* memberRemap)
{
    std::vector<AnnotationsDirectoryEntry> out = entries;
    if (memberRemap == nullptr) {
        return Ok(std::move(out));
    }
    for (AnnotationsDirectoryEntry& entry : out) {
        if (entry.memberIdx >= memberRemap->size()) {
            return Err(WriteError::InvalidModel);
        }
        entry.memberIdx = (*memberRemap)[entry.memberIdx];
    }
    std::sort(out.begin(), out.end(),
              [](const AnnotationsDirectoryEntry& a, const AnnotationsDirectoryEntry& b) {
                  return a.memberIdx < b.memberIdx;
              });
    for (ca::usize i = 1; i < out.size(); ++i) {
        if (out[i].memberIdx == out[i - 1].memberIdx) {
            return Err(WriteError::InvalidModel);
        }
    }
    return Ok(std::move(out));
}

}   // namespace

Result<std::vector<ca::u8>, WriteError> buildDex(DexFile& dex,
                                                 const BuildOptions& options)
{
    if (!dex.hasSource()) {
        return Err(WriteError::MissingSource);
    }
    if (dex.header.version >= 41) {
        return Err(WriteError::NotModeled);
    }
    if (dex.header.linkSize != 0) {
        return Err(WriteError::NotModeled);
    }
    if (dex.header.endianTag != kEndianTag) {
        return Err(WriteError::NotModeled);
    }
    if (!validIdTables(dex)) {
        return Err(WriteError::InvalidModel);
    }

    // ---- canonical 字符串池：排序、去重、建立旧→新索引映射 ----
    Result<StringPool, WriteError> collected = collectStringPool(dex);
    if (collected.is_err()) {
        return Err(collected.unwrap_err());
    }
    const StringPool pool = std::move(collected).unwrap();

    // ---- type_ids：按描述符 UTF-16 排序 ----
    const auto typeLess = [&dex, &pool](ca::u32 a, ca::u32 b) {
        return pool.keyOf(dex.typeIds[a].descriptorIdx) <
               pool.keyOf(dex.typeIds[b].descriptorIdx);
    };
    Result<IdOrder, WriteError> typeOrderResult = makeIdOrder(dex.typeCount(), typeLess);
    if (typeOrderResult.is_err()) {
        return Err(typeOrderResult.unwrap_err());
    }
    const IdOrder typeOrder = std::move(typeOrderResult).unwrap();

    // ---- proto_ids：返回类型，再参数个数，再逐参数（AOSP 比较规则）----
    std::vector<TypeListSpan> protoTypeLists(dex.protoCount());
    std::vector<std::vector<ca::u32>> protoParams(dex.protoCount());
    for (ca::u32 i = 0; i < dex.protoCount(); ++i) {
        Result<TypeListSpan, ReadError> list = dex.typeList(dex.protoIds[i].parametersOff);
        if (list.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        protoTypeLists[i] = std::move(list).unwrap();
        const TypeListSpan& span = protoTypeLists[i];
        protoParams[i].reserve(span.size);
        for (ca::u32 j = 0; j < span.size; ++j) {
            const ca::u32 typeIdx = span.at(j);
            if (typeIdx >= dex.typeCount()) {
                return Err(WriteError::InvalidModel);
            }
            protoParams[i].push_back(typeOrder.remap[typeIdx]);
        }
    }
    const auto protoLess = [&dex, &protoParams, &typeOrder](ca::u32 a, ca::u32 b) {
        const ca::u32 returnA = typeOrder.remap[dex.protoIds[a].returnTypeIdx];
        const ca::u32 returnB = typeOrder.remap[dex.protoIds[b].returnTypeIdx];
        if (returnA != returnB) {
            return returnA < returnB;
        }
        const std::vector<ca::u32>& paramsA = protoParams[a];
        const std::vector<ca::u32>& paramsB = protoParams[b];
        if (paramsA.size() != paramsB.size()) {
            return paramsA.size() < paramsB.size();
        }
        for (ca::usize i = 0; i < paramsA.size(); ++i) {
            if (paramsA[i] != paramsB[i]) {
                return paramsA[i] < paramsB[i];
            }
        }
        return false;
    };
    Result<IdOrder, WriteError> protoOrderResult = makeIdOrder(dex.protoCount(), protoLess);
    if (protoOrderResult.is_err()) {
        return Err(protoOrderResult.unwrap_err());
    }
    const IdOrder protoOrder = std::move(protoOrderResult).unwrap();

    // ---- field_ids / method_ids：按 (class, name, type/proto) 重排 ----
    const auto fieldLess = [&dex, &pool, &typeOrder](ca::u32 a, ca::u32 b) {
        const FieldId& fieldA = dex.fieldIds[a];
        const FieldId& fieldB = dex.fieldIds[b];
        const ca::u32 classA = typeOrder.remap[fieldA.classIdx];
        const ca::u32 classB = typeOrder.remap[fieldB.classIdx];
        if (classA != classB) {
            return classA < classB;
        }
        const int cmp = pool.keyOf(fieldA.nameIdx).compare(pool.keyOf(fieldB.nameIdx));
        if (cmp != 0) {
            return cmp < 0;
        }
        return typeOrder.remap[fieldA.typeIdx] < typeOrder.remap[fieldB.typeIdx];
    };
    Result<IdOrder, WriteError> fieldOrderResult = makeIdOrder(dex.fieldCount(), fieldLess);
    if (fieldOrderResult.is_err()) {
        return Err(fieldOrderResult.unwrap_err());
    }
    const IdOrder fieldOrder = std::move(fieldOrderResult).unwrap();

    const auto methodLess = [&dex, &pool, &typeOrder, &protoOrder](ca::u32 a, ca::u32 b) {
        const MethodId& methodA = dex.methodIds[a];
        const MethodId& methodB = dex.methodIds[b];
        const ca::u32 classA = typeOrder.remap[methodA.classIdx];
        const ca::u32 classB = typeOrder.remap[methodB.classIdx];
        if (classA != classB) {
            return classA < classB;
        }
        const int cmp = pool.keyOf(methodA.nameIdx).compare(pool.keyOf(methodB.nameIdx));
        if (cmp != 0) {
            return cmp < 0;
        }
        return protoOrder.remap[methodA.protoIdx] < protoOrder.remap[methodB.protoIdx];
    };
    Result<IdOrder, WriteError> methodOrderResult = makeIdOrder(dex.methodCount(), methodLess);
    if (methodOrderResult.is_err()) {
        return Err(methodOrderResult.unwrap_err());
    }
    const IdOrder methodOrder = std::move(methodOrderResult).unwrap();

    // ---- class_defs：按新的 class_idx 排序 ----
    const auto classLess = [&dex, &typeOrder](ca::u32 a, ca::u32 b) {
        return typeOrder.remap[dex.classDefs[a].classIdx] <
               typeOrder.remap[dex.classDefs[b].classIdx];
    };
    Result<IdOrder, WriteError> classOrderResult = makeIdOrder(dex.classCount(), classLess);
    if (classOrderResult.is_err()) {
        return Err(classOrderResult.unwrap_err());
    }
    const IdOrder classOrder = std::move(classOrderResult).unwrap();

    const bool indicesChanged = !pool.remapIsIdentity || !typeOrder.identity ||
                                !protoOrder.identity || !fieldOrder.identity ||
                                !methodOrder.identity || !classOrder.identity;
    if (indicesChanged && options.keepUnknownSections && !dex.rawSections.empty()) {
        return Err(WriteError::UnmappedRawSection);
    }
    const IndexRemap maps{
        pool.remap, typeOrder.remap, protoOrder.remap, fieldOrder.remap, methodOrder.remap};

    const ByteSlice source = dex.source();

    // ---- 替换项索引 ----
    std::unordered_map<ca::u32, const CodeReplacement*> replacements;
    for (const CodeReplacement& repl : options.codeReplacements) {
        if (repl.methodIdx >= dex.methodCount()) {
            return Err(WriteError::InvalidModel);
        }
        if (!replacements.emplace(repl.methodIdx, &repl).second) {
            return Err(WriteError::InvalidModel);
        }
        if (repl.insns.size() != static_cast<ca::usize>(repl.item.insnsSize) * 2u) {
            return Err(WriteError::Unencodable);
        }
    }

    // ---- 删除成员：只从 class_data 移除，ID 表条目保留 ----
    std::unordered_set<ca::u32> removedFields(options.removedFields.begin(),
                                              options.removedFields.end());
    std::unordered_set<ca::u32> removedMethods(options.removedMethods.begin(),
                                               options.removedMethods.end());
    for (ca::u32 fieldIdx : removedFields) {
        if (fieldIdx >= dex.fieldCount()) {
            return Err(WriteError::InvalidModel);
        }
    }
    for (ca::u32 methodIdx : removedMethods) {
        if (methodIdx >= dex.methodCount() || replacements.count(methodIdx) != 0) {
            return Err(WriteError::InvalidModel);
        }
    }

    // ---- class_data 与方法体目录（按旧偏移去重，保序）----
    std::map<ca::u32, const ClassData*> classDataByOff;
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        const ca::u32 off = dex.classDefs[i].classDataOff;
        if (off == 0 || classDataByOff.count(off) != 0) {
            continue;
        }
        const Result<const ClassData*, WriteError> data = requireDecoded(dex.classData(i));
        if (data.is_err()) {
            return Err(data.unwrap_err());
        }
        classDataByOff.emplace(off, data.unwrap());
    }

    std::unordered_set<ca::u32> staticValuesOffs;
    for (const ClassDef& def : dex.classDefs) {
        if (def.classDataOff != 0 && def.staticValuesOff != 0) {
            staticValuesOffs.insert(def.classDataOff);
        }
    }

    std::vector<MethodSite> sites;
    std::unordered_set<ca::u32> methodsWithCode;
    std::unordered_set<ca::u32> definedFields;
    std::unordered_set<ca::u32> definedMethods;
    std::unordered_set<ca::u32> staticFieldsWithValues;
    for (const auto& entry : classDataByOff) {
        const ClassData& data = *entry.second;
        const bool hasStaticValues = staticValuesOffs.count(entry.first) != 0;
        const std::vector<EncodedField>* fieldLists[2] = {&data.staticFields,
                                                          &data.instanceFields};
        for (ca::u32 listIdx = 0; listIdx < 2; ++listIdx) {
            for (const EncodedField& field : *fieldLists[listIdx]) {
                if (removedFields.count(field.fieldIndex) != 0) {
                    continue;
                }
                if (field.fieldIndex >= dex.fieldCount()) {
                    return Err(WriteError::InvalidModel);
                }
                definedFields.insert(field.fieldIndex);
                if (listIdx == 0 && hasStaticValues) {
                    staticFieldsWithValues.insert(field.fieldIndex);
                }
            }
        }
        const std::vector<EncodedMethod>* lists[2] = {&data.directMethods, &data.virtualMethods};
        for (const std::vector<EncodedMethod>* list : lists) {
            for (const EncodedMethod& method : *list) {
                if (removedMethods.count(method.methodIndex) != 0) {
                    continue;
                }
                if (method.methodIndex >= dex.methodCount()) {
                    return Err(WriteError::InvalidModel);
                }
                definedMethods.insert(method.methodIndex);
                if (method.codeOff == 0) {
                    continue;
                }
                if (!methodsWithCode.insert(method.methodIndex).second) {
                    return Err(WriteError::InvalidModel);  // 同一方法被两处定义
                }
                sites.push_back(MethodSite{method.methodIndex, method.codeOff});
            }
        }
    }
    for (ca::u32 fieldIdx : removedFields) {
        if (staticFieldsWithValues.count(fieldIdx) != 0) {
            return Err(WriteError::InvalidModel);  // static_values 槽位无法回收
        }
    }
    // code_item 布局按新方法索引排序，保证重排后二次重建仍是固定点。
    std::sort(sites.begin(), sites.end(),
              [&methodOrder](const MethodSite& a, const MethodSite& b) {
                  return methodOrder.remap[a.methodIdx] < methodOrder.remap[b.methodIdx];
              });
    for (const auto& entry : replacements) {
        if (methodsWithCode.count(entry.first) == 0) {
            return Err(WriteError::InvalidModel);
        }
    }

    // ---- 新增成员：校验重复定义，挂到对应 class_data 的副本 ----
    std::unordered_map<ca::u32, std::vector<const FieldAddition*>> fieldsByClass;
    std::unordered_map<ca::u32, std::vector<const MethodAddition*>> methodsByClass;
    std::unordered_set<ca::u32> addedFields;
    std::unordered_set<ca::u32> addedMethods;
    for (const FieldAddition& add : options.fieldAdditions) {
        if (add.classDefIdx >= dex.classCount() || add.fieldIdx >= dex.fieldCount()) {
            return Err(WriteError::InvalidModel);
        }
        if (definedFields.count(add.fieldIdx) != 0 ||
            removedFields.count(add.fieldIdx) != 0 ||
            !addedFields.insert(add.fieldIdx).second) {
            return Err(WriteError::InvalidModel);  // 重复定义或与删除冲突
        }
        // 静态字段必须与 static_values 数组等长；扩展数组留给后续切片。
        if (add.isStatic && dex.classDefs[add.classDefIdx].staticValuesOff != 0) {
            return Err(WriteError::InvalidModel);
        }
        fieldsByClass[add.classDefIdx].push_back(&add);
    }
    for (const MethodAddition& add : options.methodAdditions) {
        if (add.classDefIdx >= dex.classCount() || add.methodIdx >= dex.methodCount()) {
            return Err(WriteError::InvalidModel);
        }
        if (definedMethods.count(add.methodIdx) != 0 ||
            !addedMethods.insert(add.methodIdx).second ||
            replacements.count(add.methodIdx) != 0 ||
            removedMethods.count(add.methodIdx) != 0) {
            return Err(WriteError::InvalidModel);  // 重复定义或与替换/删除冲突
        }
        if (add.insns.size() != static_cast<ca::usize>(add.item.insnsSize) * 2u) {
            return Err(WriteError::Unencodable);
        }
        methodsByClass[add.classDefIdx].push_back(&add);
    }

    std::map<ca::u32, ClassData> classDataEdits;
    const auto ensureEdit = [&](ca::u32 classDefIdx) -> ClassData& {
        ClassData& edit = classDataEdits[classDefIdx];
        if (edit.raw.length == 0 && edit.staticFields.empty() &&
            edit.instanceFields.empty() && edit.directMethods.empty() &&
            edit.virtualMethods.empty()) {
            const ca::u32 off = dex.classDefs[classDefIdx].classDataOff;
            if (off != 0) {
                const auto found = classDataByOff.find(off);
                if (found != classDataByOff.end()) {
                    edit = *found->second;
                }
            }
        }
        return edit;
    };
    constexpr ca::u32 kAccPrivate = 0x2u;
    constexpr ca::u32 kAccStatic = 0x8u;
    constexpr ca::u32 kAccConstructor = 0x10000u;
    for (const auto& entry : fieldsByClass) {
        ClassData& edit = ensureEdit(entry.first);
        for (const FieldAddition* add : entry.second) {
            EncodedField field;
            field.fieldIndex = add->fieldIdx;
            field.accessFlags = add->accessFlags;
            (add->isStatic ? edit.staticFields : edit.instanceFields).push_back(field);
        }
    }
    for (const auto& entry : methodsByClass) {
        ClassData& edit = ensureEdit(entry.first);
        for (const MethodAddition* add : entry.second) {
            EncodedMethod method;
            method.methodIndex = add->methodIdx;
            method.accessFlags = add->accessFlags;
            method.codeOff = 1;  // 占位，布局后替换为真实 code_off
            const bool direct = (add->accessFlags &
                                 (kAccPrivate | kAccStatic | kAccConstructor)) != 0;
            (direct ? edit.directMethods : edit.virtualMethods).push_back(method);
        }
    }

    // ---- code_item 布局单元：共享旧 code_off 的方法合并，新增方法各自一单元 ----
    std::unordered_map<ca::u32, const CodeItem*> codeByOff;
    std::unordered_map<ca::u32, ByteSlice> insnsByOff;
    std::vector<ca::u32> codeOrder;
    for (const MethodSite& site : sites) {
        if (codeByOff.count(site.codeOff) != 0) {
            continue;
        }
        const Result<const CodeItem*, WriteError> code =
            requireDecoded(dex.codeItem(site.codeOff));
        if (code.is_err()) {
            return Err(code.unwrap_err());
        }
        const ByteSlice insns =
            subOrEmpty(source, code.unwrap()->insns.offset, code.unwrap()->insns.length);
        if (insns.size() != static_cast<ca::usize>(code.unwrap()->insnsSize) * 2u) {
            return Err(WriteError::SourceUnreadable);
        }
        codeByOff.emplace(site.codeOff, code.unwrap());
        insnsByOff.emplace(site.codeOff, insns);
        codeOrder.push_back(site.codeOff);
    }

    std::unordered_map<ca::u32, std::vector<const MethodSite*>> sitesByCode;
    for (const MethodSite& site : sites) {
        sitesByCode[site.codeOff].push_back(&site);
    }

    std::vector<CodeUnit> units;
    const auto pushUnit = [&](const CodeItem* item, ByteSlice insns, ca::u32 debugOff,
                              ca::u32 sortKey,
                              std::vector<ca::u32> methods) -> Result<void, WriteError> {
        CodeUnit unit;
        unit.item = item;
        unit.oldDebugOff = debugOff;
        unit.sortKey = sortKey;
        unit.methods = std::move(methods);
        if (indicesChanged) {
            Result<std::vector<ca::u8>, WriteError> remapped = remapInsnIndices(insns, maps);
            if (remapped.is_err()) {
                return Err(remapped.unwrap_err());
            }
            unit.remappedInsns = std::move(remapped).unwrap();
            unit.insns = ByteSlice{unit.remappedInsns.data(), unit.remappedInsns.size()};
        } else {
            unit.insns = insns;
        }
        units.push_back(std::move(unit));
        return Ok();
    };

    for (ca::u32 oldOff : codeOrder) {
        const std::vector<const MethodSite*>& owners = sitesByCode[oldOff];
        std::vector<ca::u32> kept;
        for (const MethodSite* site : owners) {
            if (replacements.count(site->methodIdx) == 0) {
                kept.push_back(site->methodIdx);
            }
        }
        if (!kept.empty()) {
            const CodeItem* code = codeByOff[oldOff];
            const ca::u32 sortKey = methodOrder.remap[kept.front()];
            const Result<void, WriteError> added =
                pushUnit(code, insnsByOff[oldOff], code->debugInfoOff, sortKey,
                         std::move(kept));
            if (added.is_err()) {
                return Err(added.unwrap_err());
            }
        }
        for (const MethodSite* site : owners) {
            const auto repl = replacements.find(site->methodIdx);
            if (repl == replacements.end()) {
                continue;
            }
            const CodeReplacement* replacement = repl->second;
            const Result<void, WriteError> added = pushUnit(
                &replacement->item,
                ByteSlice{replacement->insns.data(), replacement->insns.size()},
                replacement->item.debugInfoOff, methodOrder.remap[site->methodIdx],
                {site->methodIdx});
            if (added.is_err()) {
                return Err(added.unwrap_err());
            }
        }
    }
    for (const auto& entry : methodsByClass) {
        for (const MethodAddition* add : entry.second) {
            const Result<void, WriteError> added = pushUnit(
                &add->item, ByteSlice{add->insns.data(), add->insns.size()},
                add->item.debugInfoOff, methodOrder.remap[add->methodIdx],
                {add->methodIdx});
            if (added.is_err()) {
                return Err(added.unwrap_err());
            }
        }
    }
    // 单元按代表方法的新索引排序，方法体顺序与 class_data 顺序解耦，二次重建固定。
    std::sort(units.begin(), units.end(), [](const CodeUnit& a, const CodeUnit& b) {
        return a.sortKey < b.sortKey;
    });

    ItemTable debugInfos;
    const auto addDebugInfo = [&](ca::u32 oldOff) -> Result<void, WriteError> {
        if (oldOff == 0 || debugInfos.contains(oldOff)) {
            return Ok();
        }
        const Result<const DebugInfo*, WriteError> info = requireDecoded(dex.debugInfo(oldOff));
        if (info.is_err()) {
            return Err(info.unwrap_err());
        }
        DebugInfo copy = *info.unwrap();
        if (indicesChanged) {
            const Result<void, WriteError> remapped = remapDebugInfoIndices(copy, maps);
            if (remapped.is_err()) {
                return Err(remapped.unwrap_err());
            }
        }
        Result<std::vector<ca::u8>, WriteError> encoded = writeDebugInfo(copy);
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        debugInfos.add(oldOff, std::move(encoded).unwrap());
        return Ok();
    };
    for (const CodeUnit& unit : units) {
        const Result<void, WriteError> added = addDebugInfo(unit.oldDebugOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }

    // ---- encoded_array_item（静态初值与 call site）----
    ItemTable arrays;
    const auto addArray = [&](ca::u32 oldOff) -> Result<void, WriteError> {
        if (oldOff == 0 || arrays.contains(oldOff)) {
            return Ok();
        }
        const Result<const EncodedArrayItem*, WriteError> array =
            requireDecoded(dex.encodedArray(oldOff));
        if (array.is_err()) {
            return Err(array.unwrap_err());
        }
        Result<std::vector<ca::u8>, WriteError> encoded =
            indicesChanged ? encodeArrayRemapped(*array.unwrap(), maps)
                           : writeEncodedArrayItem(*array.unwrap());
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        arrays.add(oldOff, std::move(encoded).unwrap());
        return Ok();
    };
    for (ca::u32 i = 0; i < classOrder.oldIndexByNew.size(); ++i) {
        const Result<void, WriteError> added =
            addArray(dex.classDefs[classOrder.oldIndexByNew[i]].staticValuesOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        const Result<void, WriteError> added = addArray(site.callSiteOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }

    // ---- 注解族：目录 → 参数 ref 列表 → set → item ----
    std::set<ca::u32> directoryOffs;
    for (const ClassDef& def : dex.classDefs) {
        if (def.annotationsOff != 0) {
            directoryOffs.insert(def.annotationsOff);
        }
    }

    std::map<ca::u32, const AnnotationsDirectory*> directories;
    std::set<ca::u32> setOffs;
    std::set<ca::u32> refListOffs;
    for (ca::u32 off : directoryOffs) {
        const Result<const AnnotationsDirectory*, WriteError> directory =
            requireDecoded(dex.annotationsDirectory(off));
        if (directory.is_err()) {
            return Err(directory.unwrap_err());
        }
        const AnnotationsDirectory* dir = directory.unwrap();
        directories.emplace(off, dir);
        if (dir->classAnnotationsOff != 0) {
            setOffs.insert(dir->classAnnotationsOff);
        }
        for (const AnnotationsDirectoryEntry& entry : dir->fieldAnnotations) {
            if (entry.annotationsOff != 0) {
                setOffs.insert(entry.annotationsOff);
            }
        }
        for (const AnnotationsDirectoryEntry& entry : dir->methodAnnotations) {
            if (entry.annotationsOff != 0) {
                setOffs.insert(entry.annotationsOff);
            }
        }
        for (const AnnotationsDirectoryEntry& entry : dir->parameterAnnotations) {
            if (entry.annotationsOff != 0) {
                refListOffs.insert(entry.annotationsOff);
            }
        }
    }

    std::map<ca::u32, const AnnotationSetRefList*> refLists;
    for (ca::u32 off : refListOffs) {
        const Result<const AnnotationSetRefList*, WriteError> refList =
            requireDecoded(dex.annotationSetRefList(off));
        if (refList.is_err()) {
            return Err(refList.unwrap_err());
        }
        refLists.emplace(off, refList.unwrap());
        for (ca::u32 setOff : refList.unwrap()->annotationSetOffs) {
            if (setOff != 0) {
                setOffs.insert(setOff);
            }
        }
    }

    std::map<ca::u32, const AnnotationSetItem*> sets;
    std::set<ca::u32> annotationItemOffs;
    for (ca::u32 off : setOffs) {
        const Result<const AnnotationSetItem*, WriteError> set =
            requireDecoded(dex.annotationSet(off));
        if (set.is_err()) {
            return Err(set.unwrap_err());
        }
        sets.emplace(off, set.unwrap());
        for (ca::u32 itemOff : set.unwrap()->annotationOffs) {
            if (itemOff != 0) {
                annotationItemOffs.insert(itemOff);
            }
        }
    }

    ItemTable annotationItems;
    for (ca::u32 off : annotationItemOffs) {
        const Result<const AnnotationItem*, WriteError> item =
            requireDecoded(dex.annotationItem(off));
        if (item.is_err()) {
            return Err(item.unwrap_err());
        }
        Result<std::vector<ca::u8>, WriteError> encoded =
            indicesChanged ? encodeAnnotationItemRemapped(*item.unwrap(), maps)
                           : writeAnnotationItem(*item.unwrap());
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        annotationItems.add(off, std::move(encoded).unwrap());
    }

    // ---- type_list：按新的 type 索引重新编码 ----
    ItemTable typeLists;
    const auto addTypeList = [&](ca::u32 oldOff) -> Result<void, WriteError> {
        if (oldOff == 0 || typeLists.contains(oldOff)) {
            return Ok();
        }
        Result<TypeListSpan, ReadError> list = dex.typeList(oldOff);
        if (list.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        const TypeListSpan& span = list.unwrap();
        std::vector<ca::u8> bytes;
        appendU32(bytes, span.size);
        for (ca::u32 i = 0; i < span.size; ++i) {
            const ca::u32 typeIdx = span.at(i);
            if (typeIdx >= dex.typeCount()) {
                return Err(WriteError::InvalidModel);
            }
            appendU16(bytes, static_cast<ca::u16>(typeOrder.remap[typeIdx]));
        }
        typeLists.add(oldOff, std::move(bytes));
        return Ok();
    };
    // 按新的 proto/class 顺序收集，保证二次重建的 type_list 落位一致。
    for (ca::u32 i = 0; i < protoOrder.oldIndexByNew.size(); ++i) {
        const Result<void, WriteError> added =
            addTypeList(dex.protoIds[protoOrder.oldIndexByNew[i]].parametersOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }
    for (ca::u32 i = 0; i < classOrder.oldIndexByNew.size(); ++i) {
        const Result<void, WriteError> added =
            addTypeList(dex.classDefs[classOrder.oldIndexByNew[i]].interfacesOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }

    std::vector<ca::u32> stringOffsets(pool.strings.size(), 0);
    const ca::u32 stringCount = static_cast<ca::u32>(pool.strings.size());

    // ---- 输出骨架：ID 区 ----
    std::vector<ca::u8> out;
    out.resize(kHeaderSize, 0);
    std::vector<MapItem> mapItems;
    mapItems.push_back(MapItem{MapType::HeaderItem, 0, 1, 0});

    ca::u32 stringIdsOff = 0;
    if (stringCount != 0) {
        stringIdsOff = offsetOf(out);
        out.resize(out.size() + static_cast<ca::usize>(stringCount) * 4u, 0);
        mapItems.push_back(MapItem{MapType::StringIdItem, 0, stringCount, stringIdsOff});
    }

    ca::u32 typeIdsOff = 0;
    if (!dex.typeIds.empty()) {
        typeIdsOff = offsetOf(out);
        for (ca::u32 i = 0; i < typeOrder.oldIndexByNew.size(); ++i) {
            const TypeId& id = dex.typeIds[typeOrder.oldIndexByNew[i]];
            appendU32(out, pool.remap[id.descriptorIdx]);
        }
        mapItems.push_back(MapItem{MapType::TypeIdItem, 0, dex.typeCount(), typeIdsOff});
    }

    ca::u32 protoIdsOff = 0;
    if (!dex.protoIds.empty()) {
        protoIdsOff = offsetOf(out);
        for (ca::u32 i = 0; i < protoOrder.oldIndexByNew.size(); ++i) {
            const ProtoId& proto = dex.protoIds[protoOrder.oldIndexByNew[i]];
            appendU32(out, pool.remap[proto.shortyIdx]);
            appendU32(out, typeOrder.remap[proto.returnTypeIdx]);
            appendU32(out, 0);  // parameters_off 稍后回填
        }
        mapItems.push_back(MapItem{MapType::ProtoIdItem, 0, dex.protoCount(), protoIdsOff});
    }

    ca::u32 fieldIdsOff = 0;
    if (!dex.fieldIds.empty()) {
        fieldIdsOff = offsetOf(out);
        for (ca::u32 i = 0; i < fieldOrder.oldIndexByNew.size(); ++i) {
            const FieldId& field = dex.fieldIds[fieldOrder.oldIndexByNew[i]];
            appendU16(out, static_cast<ca::u16>(typeOrder.remap[field.classIdx]));
            appendU16(out, static_cast<ca::u16>(typeOrder.remap[field.typeIdx]));
            appendU32(out, pool.remap[field.nameIdx]);
        }
        mapItems.push_back(MapItem{MapType::FieldIdItem, 0, dex.fieldCount(), fieldIdsOff});
    }

    ca::u32 methodIdsOff = 0;
    if (!dex.methodIds.empty()) {
        methodIdsOff = offsetOf(out);
        for (ca::u32 i = 0; i < methodOrder.oldIndexByNew.size(); ++i) {
            const MethodId& method = dex.methodIds[methodOrder.oldIndexByNew[i]];
            appendU16(out, static_cast<ca::u16>(typeOrder.remap[method.classIdx]));
            appendU16(out, static_cast<ca::u16>(protoOrder.remap[method.protoIdx]));
            appendU32(out, pool.remap[method.nameIdx]);
        }
        mapItems.push_back(MapItem{MapType::MethodIdItem, 0, dex.methodCount(), methodIdsOff});
    }

    ca::u32 classDefsOff = 0;
    if (!dex.classDefs.empty()) {
        classDefsOff = offsetOf(out);
        for (ca::u32 i = 0; i < classOrder.oldIndexByNew.size(); ++i) {
            const ClassDef& def = dex.classDefs[classOrder.oldIndexByNew[i]];
            appendU32(out, typeOrder.remap[def.classIdx]);
            appendU32(out, def.accessFlags);
            appendU32(out, def.superclassIdx == DexFile::kNoIndex
                               ? DexFile::kNoIndex
                               : typeOrder.remap[def.superclassIdx]);
            appendU32(out, 0);  // interfaces_off
            appendU32(out, def.sourceFileIdx == DexFile::kNoIndex
                               ? DexFile::kNoIndex
                               : pool.remap[def.sourceFileIdx]);
            appendU32(out, 0);  // annotations_off
            appendU32(out, 0);  // class_data_off
            appendU32(out, 0);  // static_values_off
        }
        mapItems.push_back(MapItem{MapType::ClassDefItem, 0, dex.classCount(), classDefsOff});
    }

    ca::u32 callSitesOff = 0;
    if (!dex.callSites.empty()) {
        callSitesOff = offsetOf(out);
        out.resize(out.size() + dex.callSites.size() * 4u, 0);
        mapItems.push_back(
            MapItem{MapType::CallSiteIdItem, 0, dex.callSiteCount(), callSitesOff});
    }

    if (!dex.methodHandles.empty()) {
        const ca::u32 handlesOff = offsetOf(out);
        for (const MethodHandle& handle : dex.methodHandles) {
            const ca::u32 target = handle.handleType <= 3
                                       ? fieldOrder.remap[handle.targetIdx]
                                       : methodOrder.remap[handle.targetIdx];
            appendU16(out, handle.handleType);
            appendU16(out, handle.unused1);
            appendU16(out, static_cast<ca::u16>(target));
            appendU16(out, handle.unused2);
        }
        mapItems.push_back(
            MapItem{MapType::MethodHandleItem, 0, dex.methodHandleCount(), handlesOff});
    }

    alignOut(out, 4);
    const ca::u32 dataStart = offsetOf(out);

    // ---- 数据区：按依赖顺序落位 ----
    const auto place = [&out, &mapItems](ItemTable& table, ca::u32 alignment,
                                         MapType type) -> ca::u32 {
        if (table.items.empty()) {
            return 0;
        }
        const ca::u32 sectionStart = alignUp(offsetOf(out), alignment);
        out.resize(sectionStart, 0);
        for (ca::usize i = 0; i < table.items.size(); ++i) {
            out.resize(alignUp(offsetOf(out), alignment), 0);
            table.newOffsets[i] = offsetOf(out);
            const std::vector<ca::u8>& bytes = table.items[i];
            if (!bytes.empty()) {
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
        }
        mapItems.push_back(
            MapItem{type, 0, static_cast<ca::u32>(table.items.size()), sectionStart});
        return sectionStart;
    };

    if (!pool.strings.empty()) {
        const ca::u32 sectionStart = offsetOf(out);
        for (ca::usize i = 0; i < pool.strings.size(); ++i) {
            stringOffsets[i] = offsetOf(out);
            const std::vector<ca::u8>& data = pool.strings[i].data;
            out.insert(out.end(), data.begin(), data.end());
        }
        mapItems.push_back(MapItem{MapType::StringDataItem, 0, stringCount, sectionStart});
    }
    place(typeLists, 4, MapType::TypeList);
    place(arrays, 1, MapType::EncodedArrayItem);
    place(annotationItems, 1, MapType::AnnotationItem);

    const auto remap = [](const ItemTable& table, ca::u32 oldOff,
                          ca::u32* newOff) -> bool {
        if (oldOff == 0) {
            *newOff = 0;
            return true;
        }
        return table.lookup(oldOff, newOff);
    };

    ItemTable annotationSets;
    for (const auto& entry : sets) {
        std::vector<ca::u8> bytes;
        appendU32(bytes, static_cast<ca::u32>(entry.second->annotationOffs.size()));
        for (ca::u32 oldOff : entry.second->annotationOffs) {
            ca::u32 newOff = 0;
            if (!remap(annotationItems, oldOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, newOff);
        }
        annotationSets.add(entry.first, std::move(bytes));
    }
    place(annotationSets, 4, MapType::AnnotationSetItem);

    ItemTable annotationRefLists;
    for (const auto& entry : refLists) {
        std::vector<ca::u8> bytes;
        appendU32(bytes, static_cast<ca::u32>(entry.second->annotationSetOffs.size()));
        for (ca::u32 oldOff : entry.second->annotationSetOffs) {
            ca::u32 newOff = 0;
            if (!remap(annotationSets, oldOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, newOff);
        }
        annotationRefLists.add(entry.first, std::move(bytes));
    }
    place(annotationRefLists, 4, MapType::AnnotationSetRefList);

    const std::vector<ca::u32>* fieldMembers =
        fieldOrder.identity ? nullptr : &fieldOrder.remap;
    const std::vector<ca::u32>* methodMembers =
        methodOrder.identity ? nullptr : &methodOrder.remap;

    ItemTable annotationDirectories;
    for (const auto& entry : directories) {
        const AnnotationsDirectory& dir = *entry.second;
        Result<std::vector<AnnotationsDirectoryEntry>, WriteError> fieldEntries =
            remapDirectoryEntries(dir.fieldAnnotations, fieldMembers);
        Result<std::vector<AnnotationsDirectoryEntry>, WriteError> methodEntries =
            remapDirectoryEntries(dir.methodAnnotations, methodMembers);
        Result<std::vector<AnnotationsDirectoryEntry>, WriteError> parameterEntries =
            remapDirectoryEntries(dir.parameterAnnotations, methodMembers);
        if (fieldEntries.is_err() || methodEntries.is_err() || parameterEntries.is_err()) {
            return Err(WriteError::InvalidModel);
        }
        const std::vector<AnnotationsDirectoryEntry>& fields = fieldEntries.unwrap();
        const std::vector<AnnotationsDirectoryEntry>& methods = methodEntries.unwrap();
        const std::vector<AnnotationsDirectoryEntry>& parameters =
            parameterEntries.unwrap();

        std::vector<ca::u8> bytes;
        ca::u32 classOff = 0;
        if (!remap(annotationSets, dir.classAnnotationsOff, &classOff)) {
            return Err(WriteError::InvalidModel);
        }
        appendU32(bytes, classOff);
        appendU32(bytes, static_cast<ca::u32>(fields.size()));
        appendU32(bytes, static_cast<ca::u32>(methods.size()));
        appendU32(bytes, static_cast<ca::u32>(parameters.size()));
        for (const AnnotationsDirectoryEntry& e : fields) {
            ca::u32 newOff = 0;
            if (!remap(annotationSets, e.annotationsOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, e.memberIdx);
            appendU32(bytes, newOff);
        }
        for (const AnnotationsDirectoryEntry& e : methods) {
            ca::u32 newOff = 0;
            if (!remap(annotationSets, e.annotationsOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, e.memberIdx);
            appendU32(bytes, newOff);
        }
        for (const AnnotationsDirectoryEntry& e : parameters) {
            ca::u32 newOff = 0;
            if (!remap(annotationRefLists, e.annotationsOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, e.memberIdx);
            appendU32(bytes, newOff);
        }
        annotationDirectories.add(entry.first, std::move(bytes));
    }
    place(annotationDirectories, 4, MapType::AnnotationsDirectoryItem);

    place(debugInfos, 1, MapType::DebugInfoItem);

    // ---- code_item：按单元顺序落位 ----
    std::unordered_map<ca::u32, ca::u32> methodNewCode;
    if (!units.empty()) {
        const ca::u32 sectionStart = alignUp(offsetOf(out), 4);
        out.resize(sectionStart, 0);
        for (CodeUnit& unit : units) {
            alignOut(out, 4);
            CodeItem copy = *unit.item;
            if (indicesChanged) {
                for (CatchHandler& handler : copy.catchHandlers) {
                    for (TypedCatch& typed : handler.typed) {
                        if (typed.typeIdx >= maps.types.size()) {
                            return Err(WriteError::InvalidModel);
                        }
                        typed.typeIdx = maps.types[typed.typeIdx];
                    }
                }
            }
            if (unit.oldDebugOff != 0) {
                ca::u32 newOff = 0;
                if (!debugInfos.lookup(unit.oldDebugOff, &newOff)) {
                    return Err(WriteError::InvalidModel);
                }
                copy.debugInfoOff = newOff;
            } else {
                copy.debugInfoOff = 0;
            }
            Result<std::vector<ca::u8>, WriteError> encoded =
                writeCodeItem(copy, unit.insns);
            if (encoded.is_err()) {
                return Err(encoded.unwrap_err());
            }
            unit.newOffset = offsetOf(out);
            const std::vector<ca::u8>& bytes = encoded.unwrap();
            if (!bytes.empty()) {
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
            for (ca::u32 methodIdx : unit.methods) {
                methodNewCode[methodIdx] = unit.newOffset;
            }
        }
        mapItems.push_back(
            MapItem{MapType::CodeItem, 0, static_cast<ca::u32>(units.size()), sectionStart});
    }

    // ---- class_data：code_off 换成新偏移，field/method 索引换成新下标 ----
    const auto encodeClassData = [&](ClassData copy)
        -> Result<std::vector<ca::u8>, WriteError> {
        const auto fieldRemoved = [&removedFields](const EncodedField& field) {
            return removedFields.count(field.fieldIndex) != 0;
        };
        for (std::vector<EncodedField>* list : {&copy.staticFields, &copy.instanceFields}) {
            list->erase(std::remove_if(list->begin(), list->end(), fieldRemoved),
                        list->end());
        }
        const auto methodRemoved = [&removedMethods](const EncodedMethod& method) {
            return removedMethods.count(method.methodIndex) != 0;
        };
        for (std::vector<EncodedMethod>* list : {&copy.directMethods, &copy.virtualMethods}) {
            list->erase(std::remove_if(list->begin(), list->end(), methodRemoved),
                        list->end());
        }

        std::vector<EncodedField>* fieldLists[2] = {&copy.staticFields,
                                                    &copy.instanceFields};
        for (std::vector<EncodedField>* list : fieldLists) {
            for (EncodedField& field : *list) {
                if (field.fieldIndex >= fieldOrder.remap.size()) {
                    return Err(WriteError::InvalidModel);
                }
                field.fieldIndex = fieldOrder.remap[field.fieldIndex];
            }
            std::sort(list->begin(), list->end(),
                      [](const EncodedField& a, const EncodedField& b) {
                          return a.fieldIndex < b.fieldIndex;
                      });
        }

        std::vector<EncodedMethod>* methodLists[2] = {&copy.directMethods,
                                                      &copy.virtualMethods};
        for (std::vector<EncodedMethod>* list : methodLists) {
            for (EncodedMethod& method : *list) {
                const ca::u32 oldIndex = method.methodIndex;
                if (oldIndex >= methodOrder.remap.size()) {
                    return Err(WriteError::InvalidModel);
                }
                if (method.codeOff != 0) {
                    const auto newOff = methodNewCode.find(oldIndex);
                    if (newOff == methodNewCode.end()) {
                        return Err(WriteError::InvalidModel);
                    }
                    method.codeOff = newOff->second;
                }
                method.methodIndex = methodOrder.remap[oldIndex];
            }
            std::sort(list->begin(), list->end(),
                      [](const EncodedMethod& a, const EncodedMethod& b) {
                          return a.methodIndex < b.methodIndex;
                      });
        }
        return writeClassData(copy);
    };

    // 未被新增成员改写的 class_data 按旧偏移共享；被改写的类各写一份副本。
    std::unordered_set<ca::u32> usedByNonEdited;
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        if (classDataEdits.count(i) != 0) {
            continue;
        }
        const ca::u32 off = dex.classDefs[i].classDataOff;
        if (off != 0) {
            usedByNonEdited.insert(off);
        }
    }

    std::vector<std::vector<ca::u8>> classDataBlobs;
    std::unordered_map<ca::u32, ca::usize> classDataIndexByOff;
    std::unordered_map<ca::u32, ca::usize> classDataIndexByClass;
    for (const auto& entry : classDataByOff) {
        if (usedByNonEdited.count(entry.first) == 0) {
            continue;
        }
        Result<std::vector<ca::u8>, WriteError> encoded = encodeClassData(*entry.second);
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        classDataIndexByOff[entry.first] = classDataBlobs.size();
        classDataBlobs.push_back(std::move(encoded).unwrap());
    }
    for (const auto& entry : classDataEdits) {
        Result<std::vector<ca::u8>, WriteError> encoded = encodeClassData(entry.second);
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        classDataIndexByClass[entry.first] = classDataBlobs.size();
        classDataBlobs.push_back(std::move(encoded).unwrap());
    }

    std::vector<ca::u32> classDataOffsets(classDataBlobs.size(), 0);
    if (!classDataBlobs.empty()) {
        const ca::u32 sectionStart = offsetOf(out);
        for (ca::usize i = 0; i < classDataBlobs.size(); ++i) {
            classDataOffsets[i] = offsetOf(out);
            const std::vector<ca::u8>& bytes = classDataBlobs[i];
            out.insert(out.end(), bytes.begin(), bytes.end());
        }
        mapItems.push_back(MapItem{MapType::ClassDataItem, 0,
                                   static_cast<ca::u32>(classDataBlobs.size()), sectionStart});
    }

    // ---- 未建模 section：原字节透传 ----
    if (options.keepUnknownSections) {
        for (const RawSection& raw : dex.rawSections) {
            alignOut(out, 4);
            const ByteSlice bytes = subOrEmpty(source, raw.span.offset, raw.span.length);
            if (bytes.size() != raw.span.length) {
                return Err(WriteError::SourceUnreadable);
            }
            const ca::u32 sectionStart = offsetOf(out);
            if (!bytes.empty()) {
                out.insert(out.end(), bytes.data(), bytes.data() + bytes.size());
            }
            mapItems.push_back(
                MapItem{static_cast<MapType>(raw.type), 0, raw.size, sectionStart});
        }
    }

    // ---- map_list ----
    alignOut(out, 4);
    const ca::u32 mapOff = offsetOf(out);
    mapItems.push_back(MapItem{MapType::MapList, 0, 1, mapOff});
    appendU32(out, static_cast<ca::u32>(mapItems.size()));
    for (const MapItem& item : mapItems) {
        appendU16(out, static_cast<ca::u16>(item.type));
        appendU16(out, item.unused);
        appendU32(out, item.size);
        appendU32(out, item.offset);
    }

    // ---- 回填 ID 表与 class_defs ----
    for (ca::usize i = 0; i < stringOffsets.size(); ++i) {
        putU32(out, stringIdsOff + static_cast<ca::u32>(i) * 4u, stringOffsets[i]);
    }

    for (ca::u32 i = 0; i < protoOrder.oldIndexByNew.size(); ++i) {
        const ProtoId& proto = dex.protoIds[protoOrder.oldIndexByNew[i]];
        ca::u32 parameters = 0;
        if (!remap(typeLists, proto.parametersOff, &parameters)) {
            return Err(WriteError::InvalidModel);
        }
        putU32(out, protoIdsOff + i * 12u + 8u, parameters);
    }

    for (ca::u32 i = 0; i < classOrder.oldIndexByNew.size(); ++i) {
        const ca::u32 oldClassIdx = classOrder.oldIndexByNew[i];
        const ClassDef& def = dex.classDefs[oldClassIdx];
        ca::u32 interfaces = 0;
        ca::u32 annotations = 0;
        ca::u32 classData = 0;
        ca::u32 staticValues = 0;
        const auto edited = classDataIndexByClass.find(oldClassIdx);
        if (edited != classDataIndexByClass.end()) {
            classData = classDataOffsets[edited->second];
        } else if (def.classDataOff != 0) {
            const auto found = classDataIndexByOff.find(def.classDataOff);
            if (found == classDataIndexByOff.end()) {
                return Err(WriteError::InvalidModel);
            }
            classData = classDataOffsets[found->second];
        }
        if (!remap(typeLists, def.interfacesOff, &interfaces) ||
            !remap(annotationDirectories, def.annotationsOff, &annotations) ||
            !remap(arrays, def.staticValuesOff, &staticValues)) {
            return Err(WriteError::InvalidModel);
        }
        const ca::u32 base = classDefsOff + i * 32u;
        putU32(out, base + 12u, interfaces);
        putU32(out, base + 20u, annotations);
        putU32(out, base + 24u, classData);
        putU32(out, base + 28u, staticValues);
    }

    for (ca::usize i = 0; i < dex.callSites.size(); ++i) {
        ca::u32 newOff = 0;
        if (!remap(arrays, dex.callSites[i].callSiteOff, &newOff)) {
            return Err(WriteError::InvalidModel);
        }
        putU32(out, callSitesOff + static_cast<ca::u32>(i) * 4u, newOff);
    }

    // ---- header 与完整性字段 ----
    if (out.size() > 0xFFFFFFFFu) {
        return Err(WriteError::Unencodable);
    }
    const ca::u32 fileSize = offsetOf(out);
    const ca::u32 dataSize = fileSize - dataStart;
    const ca::u16 version = dex.header.version;

    out[0] = static_cast<ca::u8>('d');
    out[1] = static_cast<ca::u8>('e');
    out[2] = static_cast<ca::u8>('x');
    out[3] = static_cast<ca::u8>('\n');
    out[4] = static_cast<ca::u8>('0' + (version / 100) % 10);
    out[5] = static_cast<ca::u8>('0' + (version / 10) % 10);
    out[6] = static_cast<ca::u8>('0' + version % 10);
    out[7] = 0;

    putU32(out, 8, 0);
    putU32(out, 32, fileSize);
    putU32(out, 36, kHeaderSize);
    putU32(out, 40, kEndianTag);
    putU32(out, 44, 0);
    putU32(out, 48, 0);
    putU32(out, 52, mapOff);

    putU32(out, 56, stringCount);
    putU32(out, 60, stringIdsOff);
    putU32(out, 64, dex.typeCount());
    putU32(out, 68, typeIdsOff);
    putU32(out, 72, dex.protoCount());
    putU32(out, 76, protoIdsOff);
    putU32(out, 80, dex.fieldCount());
    putU32(out, 84, fieldIdsOff);
    putU32(out, 88, dex.methodCount());
    putU32(out, 92, methodIdsOff);
    putU32(out, 96, dex.classCount());
    putU32(out, 100, classDefsOff);

    putU32(out, 104, dataSize);
    putU32(out, 108, dataStart);

    const std::array<ca::u8, 20> signature =
        sha1Digest(ByteSlice{out.data() + 32, out.size() - 32});
    std::memcpy(out.data() + 12, signature.data(), signature.size());
    putU32(out, 8, adler32(ByteSlice{out.data() + 12, out.size() - 12}));

    return Ok(std::move(out));
}

}   // namespace dex::core
