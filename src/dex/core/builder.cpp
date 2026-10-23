/// @file        builder.cpp
/// @brief       canonical 布局重建与偏移回填。
#include "dex/core/builder.hpp"

#include <array>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "dex/core/annotation.hpp"
#include "dex/core/debug_info.hpp"
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

struct PendingCode
{
    const CodeItem* item = nullptr;
    ByteSlice insns{};
    ca::u32 oldDebugOff = 0;
    ca::u32 newOffset = 0;
};

/// @brief 复制 string_data_item 原字节（ULEB 头 + MUTF-8 + NUL）。
Result<std::vector<ca::u8>, WriteError> copyStringData(const ca::core::Bytes& source,
                                                       ca::u32 offset)
{
    Result<Reader, ReadError> reader = Reader::at(source, offset);
    if (reader.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    Reader cur = std::move(reader).unwrap();
    const Result<ca::u32, ReadError> length = readUleb128(cur);
    if (length.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }

    const ByteSlice rest = cur.remainingView();
    const void* nul = rest.empty() ? nullptr : std::memchr(rest.data(), 0, rest.size());
    if (nul == nullptr) {
        return Err(WriteError::SourceUnreadable);
    }

    const ca::usize head = cur.pos() - offset;
    const ca::usize tail = static_cast<const ca::u8*>(nul) - rest.data();
    const ca::usize total = head + tail + 1;
    const ca::u8* base = source.as_ptr();
    return Ok(std::vector<ca::u8>(base + offset, base + offset + total));
}

/// @brief 复制 type_list 原字节（u32 计数 + 类型索引）。
Result<std::vector<ca::u8>, WriteError> copyTypeList(const ca::core::Bytes& source,
                                                     ca::u32 offset)
{
    Result<Reader, ReadError> reader = Reader::at(source, offset);
    if (reader.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    Reader cur = std::move(reader).unwrap();
    const Result<ca::u32, ReadError> rsize = cur.u32();
    if (rsize.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    const ca::u32 size = rsize.unwrap();
    const ca::u64 total = 4ull + static_cast<ca::u64>(size) * 2ull;
    if (offset > source.len() || total > static_cast<ca::u64>(source.len() - offset)) {
        return Err(WriteError::SourceUnreadable);
    }
    const ca::u8* base = source.as_ptr();
    return Ok(std::vector<ca::u8>(base + offset, base + offset + total));
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

    const ca::core::Bytes& src = dex.sourceBytes();
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

    std::vector<MethodSite> sites;
    std::unordered_set<ca::u32> methodsWithCode;
    for (const auto& entry : classDataByOff) {
        const ClassData& data = *entry.second;
        const std::vector<EncodedMethod>* lists[2] = {&data.directMethods, &data.virtualMethods};
        for (const std::vector<EncodedMethod>* list : lists) {
            for (const EncodedMethod& method : *list) {
                if (method.methodIndex >= dex.methodCount()) {
                    return Err(WriteError::InvalidModel);
                }
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
    for (const auto& entry : replacements) {
        if (methodsWithCode.count(entry.first) == 0) {
            return Err(WriteError::InvalidModel);
        }
    }

    // ---- code_item 与 debug_info ----
    std::unordered_map<ca::u32, const CodeItem*> codeByOff;
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
        codeOrder.push_back(site.codeOff);
    }

    ItemTable debugInfos;
    const auto addDebugInfo = [&](ca::u32 oldOff) -> Result<void, WriteError> {
        if (oldOff == 0 || debugInfos.contains(oldOff)) {
            return Ok();
        }
        const Result<const DebugInfo*, WriteError> info = requireDecoded(dex.debugInfo(oldOff));
        if (info.is_err()) {
            return Err(info.unwrap_err());
        }
        Result<std::vector<ca::u8>, WriteError> encoded = writeDebugInfo(*info.unwrap());
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        debugInfos.add(oldOff, std::move(encoded).unwrap());
        return Ok();
    };
    for (ca::u32 oldOff : codeOrder) {
        const Result<void, WriteError> added = addDebugInfo(codeByOff[oldOff]->debugInfoOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }
    for (const CodeReplacement& repl : options.codeReplacements) {
        const Result<void, WriteError> added = addDebugInfo(repl.item.debugInfoOff);
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
            writeEncodedArrayItem(*array.unwrap());
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        arrays.add(oldOff, std::move(encoded).unwrap());
        return Ok();
    };
    for (const ClassDef& def : dex.classDefs) {
        const Result<void, WriteError> added = addArray(def.staticValuesOff);
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
        Result<std::vector<ca::u8>, WriteError> encoded = writeAnnotationItem(*item.unwrap());
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        annotationItems.add(off, std::move(encoded).unwrap());
    }

    // ---- type_list 与 string_data：原字节复制 ----
    ItemTable typeLists;
    const auto addTypeList = [&](ca::u32 oldOff) -> Result<void, WriteError> {
        if (oldOff == 0 || typeLists.contains(oldOff)) {
            return Ok();
        }
        Result<std::vector<ca::u8>, WriteError> bytes = copyTypeList(src, oldOff);
        if (bytes.is_err()) {
            return Err(bytes.unwrap_err());
        }
        typeLists.add(oldOff, std::move(bytes).unwrap());
        return Ok();
    };
    for (const ProtoId& proto : dex.protoIds) {
        const Result<void, WriteError> added = addTypeList(proto.parametersOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }
    for (const ClassDef& def : dex.classDefs) {
        const Result<void, WriteError> added = addTypeList(def.interfacesOff);
        if (added.is_err()) {
            return Err(added.unwrap_err());
        }
    }

    ItemTable strings;
    for (const StringId& id : dex.stringIds) {
        Result<std::vector<ca::u8>, WriteError> bytes = copyStringData(src, id.dataOff);
        if (bytes.is_err()) {
            return Err(bytes.unwrap_err());
        }
        strings.add(id.dataOff, std::move(bytes).unwrap());
    }

    // ---- 输出骨架：ID 区 ----
    std::vector<ca::u8> out;
    out.resize(kHeaderSize, 0);
    std::vector<MapItem> mapItems;
    mapItems.push_back(MapItem{MapType::HeaderItem, 0, 1, 0});

    ca::u32 stringIdsOff = 0;
    if (!dex.stringIds.empty()) {
        stringIdsOff = offsetOf(out);
        out.resize(out.size() + dex.stringIds.size() * 4u, 0);
        mapItems.push_back(
            MapItem{MapType::StringIdItem, 0, dex.stringCount(), stringIdsOff});
    }

    ca::u32 typeIdsOff = 0;
    if (!dex.typeIds.empty()) {
        typeIdsOff = offsetOf(out);
        for (const TypeId& id : dex.typeIds) {
            appendU32(out, id.descriptorIdx);
        }
        mapItems.push_back(MapItem{MapType::TypeIdItem, 0, dex.typeCount(), typeIdsOff});
    }

    ca::u32 protoIdsOff = 0;
    if (!dex.protoIds.empty()) {
        protoIdsOff = offsetOf(out);
        for (const ProtoId& proto : dex.protoIds) {
            appendU32(out, proto.shortyIdx);
            appendU32(out, proto.returnTypeIdx);
            appendU32(out, 0);  // parameters_off 稍后回填
        }
        mapItems.push_back(MapItem{MapType::ProtoIdItem, 0, dex.protoCount(), protoIdsOff});
    }

    ca::u32 fieldIdsOff = 0;
    if (!dex.fieldIds.empty()) {
        fieldIdsOff = offsetOf(out);
        for (const FieldId& field : dex.fieldIds) {
            appendU16(out, field.classIdx);
            appendU16(out, field.typeIdx);
            appendU32(out, field.nameIdx);
        }
        mapItems.push_back(MapItem{MapType::FieldIdItem, 0, dex.fieldCount(), fieldIdsOff});
    }

    ca::u32 methodIdsOff = 0;
    if (!dex.methodIds.empty()) {
        methodIdsOff = offsetOf(out);
        for (const MethodId& method : dex.methodIds) {
            appendU16(out, method.classIdx);
            appendU16(out, method.protoIdx);
            appendU32(out, method.nameIdx);
        }
        mapItems.push_back(MapItem{MapType::MethodIdItem, 0, dex.methodCount(), methodIdsOff});
    }

    ca::u32 classDefsOff = 0;
    if (!dex.classDefs.empty()) {
        classDefsOff = offsetOf(out);
        for (const ClassDef& def : dex.classDefs) {
            appendU32(out, def.classIdx);
            appendU32(out, def.accessFlags);
            appendU32(out, def.superclassIdx);
            appendU32(out, 0);  // interfaces_off
            appendU32(out, def.sourceFileIdx);
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
            appendU16(out, handle.handleType);
            appendU16(out, handle.unused1);
            appendU16(out, handle.targetIdx);
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

    place(strings, 1, MapType::StringDataItem);
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

    ItemTable annotationDirectories;
    for (const auto& entry : directories) {
        const AnnotationsDirectory& dir = *entry.second;
        std::vector<ca::u8> bytes;
        ca::u32 classOff = 0;
        if (!remap(annotationSets, dir.classAnnotationsOff, &classOff)) {
            return Err(WriteError::InvalidModel);
        }
        appendU32(bytes, classOff);
        appendU32(bytes, static_cast<ca::u32>(dir.fieldAnnotations.size()));
        appendU32(bytes, static_cast<ca::u32>(dir.methodAnnotations.size()));
        appendU32(bytes, static_cast<ca::u32>(dir.parameterAnnotations.size()));
        for (const AnnotationsDirectoryEntry& e : dir.fieldAnnotations) {
            ca::u32 newOff = 0;
            if (!remap(annotationSets, e.annotationsOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, e.memberIdx);
            appendU32(bytes, newOff);
        }
        for (const AnnotationsDirectoryEntry& e : dir.methodAnnotations) {
            ca::u32 newOff = 0;
            if (!remap(annotationSets, e.annotationsOff, &newOff)) {
                return Err(WriteError::InvalidModel);
            }
            appendU32(bytes, e.memberIdx);
            appendU32(bytes, newOff);
        }
        for (const AnnotationsDirectoryEntry& e : dir.parameterAnnotations) {
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

    // ---- code_item：按旧偏移共享；被替换的方法各自产出条目 ----
    std::unordered_map<ca::u32, std::vector<const MethodSite*>> sitesByCode;
    for (const MethodSite& site : sites) {
        sitesByCode[site.codeOff].push_back(&site);
    }

    std::vector<PendingCode> pending;
    std::unordered_map<ca::u32, ca::usize> methodPending;
    for (ca::u32 oldOff : codeOrder) {
        const std::vector<const MethodSite*>& owners = sitesByCode[oldOff];
        bool hasUnreplaced = false;
        for (const MethodSite* site : owners) {
            if (replacements.count(site->methodIdx) == 0) {
                hasUnreplaced = true;
                break;
            }
        }

        ca::usize keptIndex = 0;
        if (hasUnreplaced) {
            const CodeItem* code = codeByOff[oldOff];
            keptIndex = pending.size();
            pending.push_back(PendingCode{
                code, subOrEmpty(source, code->insns.offset, code->insns.length),
                code->debugInfoOff, 0});
        }
        for (const MethodSite* site : owners) {
            const auto repl = replacements.find(site->methodIdx);
            if (repl == replacements.end()) {
                methodPending[site->methodIdx] = keptIndex;
                continue;
            }
            const CodeReplacement* replacement = repl->second;
            methodPending[site->methodIdx] = pending.size();
            pending.push_back(PendingCode{
                &replacement->item,
                ByteSlice{replacement->insns.data(), replacement->insns.size()},
                replacement->item.debugInfoOff, 0});
        }
    }

    if (!pending.empty()) {
        const ca::u32 sectionStart = alignUp(offsetOf(out), 4);
        out.resize(sectionStart, 0);
        for (PendingCode& item : pending) {
            alignOut(out, 4);
            CodeItem copy = *item.item;
            if (item.oldDebugOff != 0) {
                ca::u32 newOff = 0;
                if (!debugInfos.lookup(item.oldDebugOff, &newOff)) {
                    return Err(WriteError::InvalidModel);
                }
                copy.debugInfoOff = newOff;
            } else {
                copy.debugInfoOff = 0;
            }
            Result<std::vector<ca::u8>, WriteError> encoded = writeCodeItem(copy, item.insns);
            if (encoded.is_err()) {
                return Err(encoded.unwrap_err());
            }
            item.newOffset = offsetOf(out);
            const std::vector<ca::u8>& bytes = encoded.unwrap();
            if (!bytes.empty()) {
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
        }
        mapItems.push_back(
            MapItem{MapType::CodeItem, 0, static_cast<ca::u32>(pending.size()), sectionStart});
    }

    std::unordered_map<ca::u32, ca::u32> methodNewCode;
    for (const MethodSite& site : sites) {
        const auto index = methodPending.find(site.methodIdx);
        if (index == methodPending.end()) {
            return Err(WriteError::InvalidModel);
        }
        methodNewCode[site.methodIdx] = pending[index->second].newOffset;
    }

    // ---- class_data：code_off 换成新偏移 ----
    ItemTable classDataItems;
    for (const auto& entry : classDataByOff) {
        ClassData copy = *entry.second;
        std::vector<EncodedMethod>* lists[2] = {&copy.directMethods, &copy.virtualMethods};
        for (std::vector<EncodedMethod>* list : lists) {
            for (EncodedMethod& method : *list) {
                if (method.codeOff == 0) {
                    continue;
                }
                const auto newOff = methodNewCode.find(method.methodIndex);
                if (newOff == methodNewCode.end()) {
                    return Err(WriteError::InvalidModel);
                }
                method.codeOff = newOff->second;
            }
        }
        Result<std::vector<ca::u8>, WriteError> encoded = writeClassData(copy);
        if (encoded.is_err()) {
            return Err(encoded.unwrap_err());
        }
        classDataItems.add(entry.first, std::move(encoded).unwrap());
    }
    place(classDataItems, 1, MapType::ClassDataItem);

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
    for (ca::usize i = 0; i < dex.stringIds.size(); ++i) {
        ca::u32 newOff = 0;
        if (!strings.lookup(dex.stringIds[i].dataOff, &newOff)) {
            return Err(WriteError::InvalidModel);
        }
        putU32(out, stringIdsOff + static_cast<ca::u32>(i) * 4u, newOff);
    }

    for (ca::usize i = 0; i < dex.protoIds.size(); ++i) {
        ca::u32 parameters = 0;
        if (!remap(typeLists, dex.protoIds[i].parametersOff, &parameters)) {
            return Err(WriteError::InvalidModel);
        }
        putU32(out, protoIdsOff + static_cast<ca::u32>(i) * 12u + 8u, parameters);
    }

    for (ca::usize i = 0; i < dex.classDefs.size(); ++i) {
        const ClassDef& def = dex.classDefs[i];
        ca::u32 interfaces = 0;
        ca::u32 annotations = 0;
        ca::u32 classData = 0;
        ca::u32 staticValues = 0;
        if (!remap(typeLists, def.interfacesOff, &interfaces) ||
            !remap(annotationDirectories, def.annotationsOff, &annotations) ||
            !remap(classDataItems, def.classDataOff, &classData) ||
            !remap(arrays, def.staticValuesOff, &staticValues)) {
            return Err(WriteError::InvalidModel);
        }
        const ca::u32 base = classDefsOff + static_cast<ca::u32>(i) * 32u;
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

    putU32(out, 56, dex.stringCount());
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
