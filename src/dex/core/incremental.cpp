/// @file        incremental.cpp
/// @brief       buildDex 的增量布局路径：保留源布局，未触碰条目 copy 源字节。
///
/// 与 canonical 路径（builder.cpp）的分工：canonical 把 DOM 重排成规范布局，
/// 适合表级编辑（intern/重命名后必须全表重排）；本路径假设五张 ID 表与源
/// 一致，条目与 gap 按源偏移顺序平移，未编辑且引用偏移未变的条目按源字节
/// 透传——即 libjbc writer 的「未触碰 copy、触碰的重编码」策略在 DEX 上的
/// 形态。条目级编辑（方法体替换、成员增删、标志覆盖、注解覆盖、静态初值、
/// 剥离）的语义来自共享的 @ref builder_edit，两条路径产出等价内容。
///
/// 布局迭代：class_data 的 code_off 是 ULEB 变长，偏移平移可能改变其宽度，
/// 再次改变后续条目的落位；布局最多迭代 4 轮求固定点，不收敛返回
/// `Unencodable`。无编辑时所有条目透传、零平移，输出与源逐字节一致。
#include "dex/core/builder.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "dex/core/annotation.hpp"
#include "dex/core/builder_edit.hpp"
#include "dex/core/debug_info.hpp"
#include "dex/core/integrity.hpp"

namespace dex::core {

namespace {

constexpr ca::u32 kHeaderSize = 0x70;
constexpr ca::u32 kEndianTag = 0x12345678u;

/// 合成键（源偏移域之外）；源文件大小护栏保证与源偏移不重叠。
constexpr ca::u32 kSourceOffsetLimit = 0x40000000u;
constexpr ca::u32 kIncReplacedCodeKeyBase = 0x79000000u;  // + methodIdx
constexpr ca::u32 kIncAddedCodeKeyBase = 0x7A000000u;     // + methodIdx
constexpr ca::u32 kIncClassDataKeyBase = 0x7B000000u;     // + classDefIdx
constexpr ca::u32 kIncArrayKeyBase = 0x7C000000u;         // + classDefIdx
constexpr ca::u32 kMaxLayoutPasses = 4;

/// @brief 布局条目的种类；对齐与 map section 归属由 kind 决定。
enum class Kind : ca::u8 {
    Header,
    StringIds,
    TypeIds,
    ProtoIds,
    FieldIds,
    MethodIds,
    ClassDefs,
    CallSites,
    MethodHandles,
    StringData,
    TypeList,
    EncodedArray,
    AnnotationItem,
    AnnotationSet,
    AnnotationSetRefList,
    AnnotationsDirectory,
    DebugInfo,
    CodeItem,
    ClassData,
    UnknownSection,
    MapList,
};

ca::u32 mapTypeOf(Kind kind, ca::u32 rawType) noexcept
{
    switch (kind) {
        case Kind::Header: return static_cast<ca::u32>(MapType::HeaderItem);
        case Kind::StringIds: return static_cast<ca::u32>(MapType::StringIdItem);
        case Kind::TypeIds: return static_cast<ca::u32>(MapType::TypeIdItem);
        case Kind::ProtoIds: return static_cast<ca::u32>(MapType::ProtoIdItem);
        case Kind::FieldIds: return static_cast<ca::u32>(MapType::FieldIdItem);
        case Kind::MethodIds: return static_cast<ca::u32>(MapType::MethodIdItem);
        case Kind::ClassDefs: return static_cast<ca::u32>(MapType::ClassDefItem);
        case Kind::CallSites: return static_cast<ca::u32>(MapType::CallSiteIdItem);
        case Kind::MethodHandles: return static_cast<ca::u32>(MapType::MethodHandleItem);
        case Kind::TypeList: return static_cast<ca::u32>(MapType::TypeList);
        case Kind::AnnotationSet: return static_cast<ca::u32>(MapType::AnnotationSetItem);
        case Kind::AnnotationSetRefList:
            return static_cast<ca::u32>(MapType::AnnotationSetRefList);
        case Kind::AnnotationsDirectory:
            return static_cast<ca::u32>(MapType::AnnotationsDirectoryItem);
        case Kind::DebugInfo: return static_cast<ca::u32>(MapType::DebugInfoItem);
        case Kind::CodeItem: return static_cast<ca::u32>(MapType::CodeItem);
        case Kind::StringData: return static_cast<ca::u32>(MapType::StringDataItem);
        case Kind::EncodedArray: return static_cast<ca::u32>(MapType::EncodedArrayItem);
        case Kind::AnnotationItem: return static_cast<ca::u32>(MapType::AnnotationItem);
        case Kind::ClassData: return static_cast<ca::u32>(MapType::ClassDataItem);
        case Kind::MapList: return static_cast<ca::u32>(MapType::MapList);
        case Kind::UnknownSection: return rawType;
    }
    return rawType;
}

/// @brief map type → 走查用的条目 kind；仅限自描述段，表类返回 nullopt。
std::optional<Kind> kindOfMapType(ca::u32 mapType) noexcept
{
    switch (mapType) {
        case static_cast<ca::u32>(MapType::TypeList): return Kind::TypeList;
        case static_cast<ca::u32>(MapType::AnnotationSetItem): return Kind::AnnotationSet;
        case static_cast<ca::u32>(MapType::AnnotationSetRefList):
            return Kind::AnnotationSetRefList;
        case static_cast<ca::u32>(MapType::AnnotationItem): return Kind::AnnotationItem;
        case static_cast<ca::u32>(MapType::EncodedArrayItem): return Kind::EncodedArray;
        case static_cast<ca::u32>(MapType::DebugInfoItem): return Kind::DebugInfo;
        default: return std::nullopt;
    }
}

/// @brief 单个自描述条目的源字节宽度；解析失败或不可判长返回 Err。
Result<ca::u32, ReadError> itemLengthOf(DexFile& dex, Kind kind, ca::u32 off)
{
    switch (kind) {
        case Kind::TypeList:
        {
            Result<TypeListSpan, ReadError> list = dex.typeList(off);
            if (list.is_err()) {
                return Err(list.unwrap_err());
            }
            return Ok(list.unwrap().raw.length);
        }
        case Kind::AnnotationSet:
        {
            Result<const AnnotationSetItem*, ReadError> set = dex.annotationSet(off);
            if (set.is_err() || set.unwrap() == nullptr) {
                return Err(ReadError::Truncated);
            }
            return Ok(set.unwrap()->raw.length);
        }
        case Kind::AnnotationSetRefList:
        {
            Result<const AnnotationSetRefList*, ReadError> list = dex.annotationSetRefList(off);
            if (list.is_err() || list.unwrap() == nullptr) {
                return Err(ReadError::Truncated);
            }
            return Ok(list.unwrap()->raw.length);
        }
        case Kind::AnnotationItem:
        {
            Result<const AnnotationItem*, ReadError> item = dex.annotationItem(off);
            if (item.is_err() || item.unwrap() == nullptr) {
                return Err(ReadError::Truncated);
            }
            return Ok(item.unwrap()->raw.length);
        }
        case Kind::EncodedArray:
        {
            Result<const EncodedArrayItem*, ReadError> array = dex.encodedArray(off);
            if (array.is_err() || array.unwrap() == nullptr) {
                return Err(ReadError::Truncated);
            }
            return Ok(array.unwrap()->raw.length);
        }
        case Kind::DebugInfo:
        {
            Result<const DebugInfo*, ReadError> info = dex.debugInfo(off);
            if (info.is_err() || info.unwrap() == nullptr) {
                return Err(ReadError::Truncated);
            }
            return Ok(info.unwrap()->raw.length);
        }
        default:
            return Err(ReadError::Truncated);
    }
}

/// @brief kind 的规范对齐；源条目在源里本就不对齐时退化为 1，保证无编辑时
/// 透传布局逐字节跟随源。
ca::u32 alignmentOf(Kind kind) noexcept
{
    switch (kind) {
        case Kind::StringIds:
        case Kind::TypeIds:
        case Kind::ProtoIds:
        case Kind::FieldIds:
        case Kind::MethodIds:
        case Kind::ClassDefs:
        case Kind::CallSites:
        case Kind::MethodHandles:
        case Kind::TypeList:
        case Kind::AnnotationSet:
        case Kind::AnnotationSetRefList:
        case Kind::AnnotationsDirectory:
        case Kind::CodeItem:
        case Kind::MapList:
            return 4;
        default:
            return 1;
    }
}

/// @brief 一个待布局条目：源条目（透传或重编码）或编辑产生的合成条目。
struct Entry
{
    Kind kind = Kind::StringData;
    ca::u32 key = 0;        ///< 源偏移或合成键
    ca::u32 rawMapType = 0; ///< UnknownSection 的原始 map type
    ca::u32 oldOff = 0;     ///< 源起始；合成条目为 0
    ca::u32 oldLen = 0;     ///< 源长度；合成条目为 0
    bool synthetic = false; ///< 编辑产生的合成条目（无源区间）
    bool removed = false;   ///< 编辑后不可达，不发射

    // 源结构缓存（透传判定与重编码用；指针指向 DexFile 懒缓存或本文件持有的
    // 解码结果，模型存活期内稳定）。
    const CodeItem* code = nullptr;
    const ClassData* classData = nullptr;
    const AnnotationSetItem* set = nullptr;
    const AnnotationSetRefList* refList = nullptr;
    const AnnotationsDirectory* directory = nullptr;

    // 合成条目的内容来源。
    const CodeReplacement* replacement = nullptr;  // 替换方法体
    const MethodAddition* addition = nullptr;      // 注入方法体
    const ClassData* effectiveClassData = nullptr; // 合成 class_data 的成员目录
    ca::u32 ownedTypeListIdx = DexFile::kNoIndex;  // 自有 type_list 池下标
    std::vector<ca::u32> ownedSetItems;            // 自有 set 引用的注解项池下标
    std::vector<ca::u32> ownedRefListSets;         // 自有 ref_list 引用的 set 键
    const std::vector<AnnotationsDirectoryEntry>* directoryFields = nullptr;
    const std::vector<AnnotationsDirectoryEntry>* directoryMethods = nullptr;
    const std::vector<AnnotationsDirectoryEntry>* directoryParameters = nullptr;
    ca::u32 directoryClassSetKey = 0;
    std::vector<ca::u8> constantBytes;  ///< 内容与偏移无关的合成条目（一次编码）
    std::vector<ca::u32> users;         ///< 引用该 class_data 条目的非编辑类（共享去重）

    // 布局产物（每轮更新）。
    bool passthrough = true;
    std::vector<ca::u8> encoded;
    ca::u32 newOff = 0;

    ca::u32 len() const noexcept
    {
        return passthrough ? oldLen : static_cast<ca::u32>(encoded.size());
    }

    /// @brief 排序键：源条目按源偏移；合成条目紧贴同 kind 源组尾（或 map 前）。
    std::pair<ca::u64, ca::u32> sortKey(ca::u32 tailAnchor) const noexcept
    {
        if (!synthetic) {
            return {(static_cast<ca::u64>(oldOff) << 1) | 0u, 0u};
        }
        const ca::u32 anchor = oldOff != 0 ? oldOff : tailAnchor;
        return {(static_cast<ca::u64>(anchor) << 1) | 1u, mapTypeOf(kind, rawMapType)};
    }
};

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

void putU32(std::vector<ca::u8>& out, ca::usize offset, ca::u32 value)
{
    out[offset] = static_cast<ca::u8>(value & 0xFFu);
    out[offset + 1] = static_cast<ca::u8>((value >> 8) & 0xFFu);
    out[offset + 2] = static_cast<ca::u8>((value >> 16) & 0xFFu);
    out[offset + 3] = static_cast<ca::u8>(value >> 24);
}

ca::u32 alignUp(ca::u32 value, ca::u32 alignment) noexcept
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

/// @brief 源 class_def 表快照：发现走源引用图，DOM 的 erase 不影响发现。
struct SourceClassDef
{
    ca::u32 classIdx = 0;
    ca::u32 accessFlags = 0;
    ca::u32 superclassIdx = 0;
    ca::u32 interfacesOff = 0;
    ca::u32 sourceFileIdx = 0;
    ca::u32 annotationsOff = 0;
    ca::u32 classDataOff = 0;
    ca::u32 staticValuesOff = 0;
};

Result<std::vector<SourceClassDef>, WriteError> readSourceClassDefs(ByteSlice source,
                                                                    const DexHeader& header)
{
    std::vector<SourceClassDef> out(header.classDefsSize);
    if (header.classDefsSize == 0) {
        return Ok(std::move(out));
    }
    const ca::u64 span = static_cast<ca::u64>(header.classDefsSize) * 32u;
    if (header.classDefsOff == 0 ||
        span > static_cast<ca::u64>(source.size() - header.classDefsOff)) {
        return Err(WriteError::SourceUnreadable);
    }
    for (ca::u32 i = 0; i < header.classDefsSize; ++i) {
        const ca::u8* p =
            source.data() + header.classDefsOff + static_cast<ca::usize>(i) * 32u;
        const auto readU32 = [&p]() {
            const ca::u32 v = static_cast<ca::u32>(p[0]) |
                              (static_cast<ca::u32>(p[1]) << 8) |
                              (static_cast<ca::u32>(p[2]) << 16) |
                              (static_cast<ca::u32>(p[3]) << 24);
            p += 4;
            return v;
        };
        SourceClassDef& def = out[i];
        def.classIdx = readU32();
        def.accessFlags = readU32();
        def.superclassIdx = readU32();
        def.interfacesOff = readU32();
        def.sourceFileIdx = readU32();
        def.annotationsOff = readU32();
        def.classDataOff = readU32();
        def.staticValuesOff = readU32();
    }
    return Ok(std::move(out));
}

/// @brief code_item 的完整源长度（头部 + insns + 对齐 + tries + handlers）。
ca::u32 codeItemSpan(const CodeItem& item) noexcept
{
    if (item.handlers.length != 0) {
        return item.handlers.offset + item.handlers.length - item.offset;
    }
    return item.raw.length;
}

/// @brief 布局期间的偏移解析：源偏移走区间表二分，合成键走哈希表。
class OffsetMap
{
public:
    static constexpr ca::u32 kDangling = 0xFFFFFFFEu;

    void resetIdentity(ca::u32 fileSize)
    {
        segments_.assign(1, Segment{0, fileSize, 0});
        keyOffsets_.clear();
    }

    void addSegment(ca::u32 oldStart, ca::u32 oldLen, ca::u32 newStart)
    {
        segments_.push_back(Segment{oldStart, oldLen, newStart});
    }

    void addKey(ca::u32 key, ca::u32 newOff) { keyOffsets_[key] = newOff; }

    void sortSegments()
    {
        std::sort(segments_.begin(), segments_.end(),
                  [](const Segment& a, const Segment& b) { return a.oldStart < b.oldStart; });
    }

    /// @brief 把源偏移或合成键解析为新偏移；0/kNoIndex 归零，悬垂返回 kDangling。
    ca::u32 resolve(ca::u32 key) const
    {
        if (key == 0 || key == DexFile::kNoIndex) {
            return 0;
        }
        if (key >= kSourceOffsetLimit) {
            const auto it = keyOffsets_.find(key);
            return it == keyOffsets_.end() ? kDangling : it->second;
        }
        ca::usize lo = 0;
        ca::usize hi = segments_.size();
        while (lo < hi) {
            const ca::usize mid = lo + (hi - lo) / 2;
            if (segments_[mid].oldStart + segments_[mid].oldLen <= key) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if (lo == segments_.size() || key < segments_[lo].oldStart) {
            return kDangling;
        }
        return segments_[lo].newStart + (key - segments_[lo].oldStart);
    }

private:
    struct Segment
    {
        ca::u32 oldStart = 0;
        ca::u32 oldLen = 0;
        ca::u32 newStart = 0;
    };

    std::vector<Segment> segments_;
    std::unordered_map<ca::u32, ca::u32> keyOffsets_;
};

/// @brief 一轮布局的线性扫描结果：各条目新偏移与源区间映射。
struct Layout
{
    ca::u32 total = 0;             ///< 输出总长（不含 map 尾差；map 条目计入）
    OffsetMap offsets;             ///< 源偏移/合成键 → 新偏移
    std::vector<ca::u32> gapPad;   ///< 与 entries 对齐：每条目前的对齐补零
};

}   // namespace

Result<std::vector<ca::u8>, WriteError> buildDexIncremental(DexFile& dex,
                                                            const BuildOptions& options)
{
    // ---- 入口护栏：与 canonical 相同的结构闸门 ----
    if (!dex.hasSource()) {
        return Err(WriteError::MissingSource);
    }
    if (dex.header.version >= 41 || dex.header.linkSize != 0 ||
        dex.header.endianTag != kEndianTag) {
        return Err(WriteError::NotModeled);
    }
    if (!validIdTables(dex)) {
        return Err(WriteError::InvalidModel);
    }
    const ByteSlice source = dex.source();
    if (source.size() >= kSourceOffsetLimit) {
        return Err(WriteError::NotIncremental);  // 键空间与源偏移重叠，走 canonical
    }

    // ---- 增量前提：编辑不触及 ID 表 ----
    const DexHeader& header = dex.header;
    if (dex.stringIds.size() != header.stringIdsSize ||
        dex.typeIds.size() != header.typeIdsSize ||
        dex.protoIds.size() != header.protoIdsSize ||
        dex.fieldIds.size() != header.fieldIdsSize ||
        dex.methodIds.size() != header.methodIdsSize ||
        dex.classDefs.size() > header.classDefsSize) {
        return Err(WriteError::NotIncremental);
    }
    for (const StringId& id : dex.stringIds) {
        if (id.owned) {
            return Err(WriteError::NotIncremental);
        }
    }
    for (const ProtoId& proto : dex.protoIds) {
        if (proto.ownedParameters) {
            return Err(WriteError::NotIncremental);
        }
    }
    // 布局元数据必须可信：map 缺失、偏移非升序或同 type 多条目时不做增量。
    {
        std::set<ca::u32> mapTypes;
        ca::u32 previous = 0;
        for (const MapItem& item : dex.mapItems) {
            if (item.offset < previous ||
                !mapTypes.insert(static_cast<ca::u32>(item.type)).second) {
                return Err(WriteError::SourceUnreadable);
            }
            previous = item.offset;
        }
        if (dex.mapItems.empty() || header.mapOff == 0) {
            return Err(WriteError::SourceUnreadable);
        }
    }

    Result<std::vector<SourceClassDef>, WriteError> srcDefsResult =
        readSourceClassDefs(source, header);
    if (srcDefsResult.is_err()) {
        return Err(srcDefsResult.unwrap_err());
    }
    const std::vector<SourceClassDef> srcDefs = std::move(srcDefsResult).unwrap();

    // ---- 源条目发现：从源引用图枚举全部条目（共享去重）----
    std::vector<Entry> entries;
    std::unordered_map<ca::u32, ca::usize> entryIndexByKey;
    std::vector<std::unique_ptr<ClassData>> decodedClassDatas;
    std::map<ca::u32, const ClassData*> classDataByOff;

    const auto entryAt = [&](ca::u32 key) -> Entry* {
        const auto it = entryIndexByKey.find(key);
        return it == entryIndexByKey.end() ? nullptr : &entries[it->second];
    };
    const auto addEntry = [&](Entry entry) -> Entry& {
        entryIndexByKey.emplace(entry.key, entries.size());
        entries.push_back(std::move(entry));
        return entries.back();
    };
    const auto ensureEntry = [&](Kind kind, ca::u32 off) -> Result<Entry*, WriteError> {
        if (off == 0) {
            return Err(WriteError::InvalidModel);
        }
        if (Entry* existing = entryAt(off); existing != nullptr) {
            if (existing->kind != kind) {
                return Err(WriteError::SourceUnreadable);  // 同偏移两种条目
            }
            return Ok(existing);
        }
        Entry e;
        e.kind = kind;
        e.key = off;
        e.oldOff = off;
        return Ok(&addEntry(std::move(e)));
    };
    const auto requireSpan = [&](ca::u32 off, ca::u32 len) -> Result<void, WriteError> {
        if (!covers(source, off, len)) {
            return Err(WriteError::SourceUnreadable);
        }
        return Ok();
    };

    // 定长表与固定区（表条目 key 即表起始偏移）。
    {
        const ca::u32 fixed = static_cast<ca::u32>(source.size());
        (void)fixed;
        Entry head;
        head.kind = Kind::Header;
        head.oldOff = 0;
        head.oldLen = kHeaderSize;
        addEntry(std::move(head));

        const auto table = [&](Kind kind, ca::u32 off, ca::u64 bytes) -> Result<void, WriteError> {
            if (bytes == 0) {
                return Ok();
            }
            if (off == 0 || !covers(source, off, static_cast<ca::usize>(bytes))) {
                return Err(WriteError::SourceUnreadable);
            }
            Entry& e = addEntry(Entry{});
            e.kind = kind;
            e.key = off;
            e.oldOff = off;
            e.oldLen = static_cast<ca::u32>(bytes);
            return Ok();
        };
        Result<void, WriteError> spanOk =
            table(Kind::StringIds, header.stringIdsOff,
                  static_cast<ca::u64>(header.stringIdsSize) * 4u);
        if (spanOk.is_ok()) {
            spanOk = table(Kind::TypeIds, header.typeIdsOff,
                           static_cast<ca::u64>(header.typeIdsSize) * 4u);
        }
        if (spanOk.is_ok()) {
            spanOk = table(Kind::ProtoIds, header.protoIdsOff,
                           static_cast<ca::u64>(header.protoIdsSize) * 12u);
        }
        if (spanOk.is_ok()) {
            spanOk = table(Kind::FieldIds, header.fieldIdsOff,
                           static_cast<ca::u64>(header.fieldIdsSize) * 8u);
        }
        if (spanOk.is_ok()) {
            spanOk = table(Kind::MethodIds, header.methodIdsOff,
                           static_cast<ca::u64>(header.methodIdsSize) * 8u);
        }
        if (spanOk.is_ok()) {
            spanOk = table(Kind::ClassDefs, header.classDefsOff,
                           static_cast<ca::u64>(header.classDefsSize) * 32u);
        }
        if (spanOk.is_err()) {
            return Err(spanOk.unwrap_err());
        }
        if (const MapItem* item = dex.findMapItem(MapType::CallSiteIdItem);
            item != nullptr && item->size != 0) {
            Result<void, WriteError> r =
                table(Kind::CallSites, item->offset, static_cast<ca::u64>(item->size) * 4u);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
        if (const MapItem* item = dex.findMapItem(MapType::MethodHandleItem);
            item != nullptr && item->size != 0) {
            Result<void, WriteError> r =
                table(Kind::MethodHandles, item->offset, static_cast<ca::u64>(item->size) * 8u);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
        Entry map;
        map.kind = Kind::MapList;
        map.key = header.mapOff;
        map.oldOff = header.mapOff;
        map.oldLen = static_cast<ca::u32>(4u + dex.mapItems.size() * 12u);
        Result<void, WriteError> r =
            requireSpan(map.oldOff, static_cast<ca::usize>(map.oldLen));
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
        addEntry(std::move(map));
    }

    // string_data：长度用完整 string_data_item 编码（含 ULEB 与 NUL）。
    for (ca::u32 i = 0; i < dex.stringCount(); ++i) {
        const ca::u32 dataOff = dex.stringIds[i].dataOff;
        Result<Entry*, WriteError> ensured = ensureEntry(Kind::StringData, dataOff);
        if (ensured.is_err()) {
            return Err(ensured.unwrap_err());
        }
        Entry* e = ensured.unwrap();
        if (e->oldLen != 0) {
            continue;  // 共享 string_data，长度已定
        }
        Result<std::vector<ca::u8>, ReadError> data = dex.stringData(i);
        if (data.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        e->oldLen = static_cast<ca::u32>(data.unwrap().size());
        Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    // proto 参数 type_list。
    for (const ProtoId& proto : dex.protoIds) {
        if (proto.parametersOff == 0) {
            continue;
        }
        Result<TypeListSpan, ReadError> list = dex.typeList(proto.parametersOff);
        if (list.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        Result<Entry*, WriteError> ensured = ensureEntry(Kind::TypeList, proto.parametersOff);
        if (ensured.is_err()) {
            return Err(ensured.unwrap_err());
        }
        ensured.unwrap()->oldLen = list.unwrap().raw.length;
    }

    // 源类引用：接口、注解目录、class_data、静态初值；class_data → code → debug。
    const auto ensureClassData = [&](ca::u32 off) -> Result<Entry*, WriteError> {
        Result<Entry*, WriteError> ensured = ensureEntry(Kind::ClassData, off);
        if (ensured.is_err()) {
            return ensured;
        }
        Entry* e = ensured.unwrap();
        if (e->classData != nullptr) {
            return Ok(e);
        }
        Result<ClassData, ReadError> parsed =
            parseClassData(source, off, dex.fieldCount(), dex.methodCount());
        if (parsed.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        decodedClassDatas.push_back(std::make_unique<ClassData>(std::move(parsed).unwrap()));
        e->classData = decodedClassDatas.back().get();
        e->oldLen = e->classData->raw.length;
        classDataByOff.emplace(off, e->classData);
        return Ok(e);
    };
    const auto ensureCode = [&](ca::u32 off) -> Result<Entry*, WriteError> {
        Result<Entry*, WriteError> ensured = ensureEntry(Kind::CodeItem, off);
        if (ensured.is_err()) {
            return ensured;
        }
        Entry* e = ensured.unwrap();
        if (e->code != nullptr) {
            return Ok(e);
        }
        Result<const CodeItem*, ReadError> item = dex.codeItem(off);
        if (item.is_err() || item.unwrap() == nullptr) {
            return Err(WriteError::SourceUnreadable);
        }
        e->code = item.unwrap();
        e->oldLen = codeItemSpan(*e->code);
        Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
        if (r.is_err()) {
            return Err(r.unwrap_err());
        }
        if (!options.stripDebugInfo && e->code->debugInfoOff != 0) {
            Result<Entry*, WriteError> debug =
                ensureEntry(Kind::DebugInfo, e->code->debugInfoOff);
            if (debug.is_err()) {
                return Err(debug.unwrap_err());
            }
            Entry* d = debug.unwrap();
            if (d->oldLen == 0) {
                Result<const DebugInfo*, ReadError> info = dex.debugInfo(d->oldOff);
                if (info.is_err() || info.unwrap() == nullptr) {
                    return Err(WriteError::SourceUnreadable);
                }
                d->oldLen = info.unwrap()->raw.length;
                Result<void, WriteError> dr = requireSpan(d->oldOff, d->oldLen);
                if (dr.is_err()) {
                    return Err(dr.unwrap_err());
                }
            }
        }
        return Ok(e);
    };

    for (const SourceClassDef& def : srcDefs) {
        if (def.interfacesOff != 0) {
            Result<TypeListSpan, ReadError> list = dex.typeList(def.interfacesOff);
            if (list.is_err()) {
                return Err(WriteError::SourceUnreadable);
            }
            Result<Entry*, WriteError> ensured = ensureEntry(Kind::TypeList, def.interfacesOff);
            if (ensured.is_err()) {
                return Err(ensured.unwrap_err());
            }
            ensured.unwrap()->oldLen = list.unwrap().raw.length;
        }
        if (def.annotationsOff != 0) {
            Result<Entry*, WriteError> ensured =
                ensureEntry(Kind::AnnotationsDirectory, def.annotationsOff);
            if (ensured.is_err()) {
                return Err(ensured.unwrap_err());
            }
            Entry* e = ensured.unwrap();
            if (e->directory == nullptr) {
                Result<const AnnotationsDirectory*, ReadError> dir =
                    dex.annotationsDirectory(def.annotationsOff);
                if (dir.is_err() || dir.unwrap() == nullptr) {
                    return Err(WriteError::SourceUnreadable);
                }
                e->directory = dir.unwrap();
                e->oldLen = e->directory->raw.length;
                Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
                if (r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
        }
        if (def.classDataOff != 0) {
            Result<Entry*, WriteError> ensured = ensureClassData(def.classDataOff);
            if (ensured.is_err()) {
                return Err(ensured.unwrap_err());
            }
            const ClassData* data = ensured.unwrap()->classData;
            const std::vector<EncodedMethod>* lists[2] = {&data->directMethods,
                                                          &data->virtualMethods};
            for (const std::vector<EncodedMethod>* list : lists) {
                for (const EncodedMethod& method : *list) {
                    if (method.codeOff == 0) {
                        continue;
                    }
                    Result<Entry*, WriteError> code = ensureCode(method.codeOff);
                    if (code.is_err()) {
                        return Err(code.unwrap_err());
                    }
                }
            }
        }
        if (def.staticValuesOff != 0) {
            Result<Entry*, WriteError> ensured =
                ensureEntry(Kind::EncodedArray, def.staticValuesOff);
            if (ensured.is_err()) {
                return Err(ensured.unwrap_err());
            }
            Entry* e = ensured.unwrap();
            if (e->oldLen == 0) {
                Result<const EncodedArrayItem*, ReadError> array =
                    dex.encodedArray(def.staticValuesOff);
                if (array.is_err() || array.unwrap() == nullptr) {
                    return Err(WriteError::SourceUnreadable);
                }
                e->oldLen = array.unwrap()->raw.length;
                Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
                if (r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        Result<Entry*, WriteError> ensured = ensureEntry(Kind::EncodedArray, site.callSiteOff);
        if (ensured.is_err()) {
            return Err(ensured.unwrap_err());
        }
        Entry* e = ensured.unwrap();
        if (e->oldLen == 0) {
            Result<const EncodedArrayItem*, ReadError> array = dex.encodedArray(site.callSiteOff);
            if (array.is_err() || array.unwrap() == nullptr) {
                return Err(WriteError::SourceUnreadable);
            }
            e->oldLen = array.unwrap()->raw.length;
            Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
    }

    // 注解目录 → set/ref_list → item 的引用闭包（从已发现目录走源图）。
    {
        std::vector<ca::u32> pendingDirectories;
        for (const Entry& e : entries) {
            if (e.kind == Kind::AnnotationsDirectory) {
                pendingDirectories.push_back(e.key);
            }
        }
        const auto ensureSet = [&](ca::u32 off) -> Result<Entry*, WriteError> {
            Result<Entry*, WriteError> ensured = ensureEntry(Kind::AnnotationSet, off);
            if (ensured.is_err()) {
                return ensured;
            }
            Entry* e = ensured.unwrap();
            if (e->set == nullptr) {
                Result<const AnnotationSetItem*, ReadError> set = dex.annotationSet(off);
                if (set.is_err() || set.unwrap() == nullptr) {
                    return Err(WriteError::SourceUnreadable);
                }
                e->set = set.unwrap();
                e->oldLen = e->set->raw.length;
                Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
                if (r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
            return Ok(e);
        };
        const auto ensureRefList = [&](ca::u32 off) -> Result<Entry*, WriteError> {
            Result<Entry*, WriteError> ensured = ensureEntry(Kind::AnnotationSetRefList, off);
            if (ensured.is_err()) {
                return ensured;
            }
            Entry* e = ensured.unwrap();
            if (e->refList == nullptr) {
                Result<const AnnotationSetRefList*, ReadError> list = dex.annotationSetRefList(off);
                if (list.is_err() || list.unwrap() == nullptr) {
                    return Err(WriteError::SourceUnreadable);
                }
                e->refList = list.unwrap();
                e->oldLen = e->refList->raw.length;
                Result<void, WriteError> r = requireSpan(e->oldOff, e->oldLen);
                if (r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
            return Ok(e);
        };
        for (ca::usize di = 0; di < pendingDirectories.size(); ++di) {
            const Entry* dir = entryAt(pendingDirectories[di]);
            const AnnotationsDirectory* content = dir->directory;
            const ca::u32 setKeys[] = {content->classAnnotationsOff};
            for (ca::u32 key : setKeys) {
                if (key != 0) {
                    Result<Entry*, WriteError> e = ensureSet(key);
                    if (e.is_err()) {
                        return Err(e.unwrap_err());
                    }
                }
            }
            const std::vector<AnnotationsDirectoryEntry>* groups[3] = {
                &content->fieldAnnotations, &content->methodAnnotations,
                &content->parameterAnnotations};
            for (const std::vector<AnnotationsDirectoryEntry>* group : groups) {
                for (const AnnotationsDirectoryEntry& entry : *group) {
                    if (entry.annotationsOff == 0) {
                        continue;
                    }
                    if (group == &content->parameterAnnotations) {
                        Result<Entry*, WriteError> refList = ensureRefList(entry.annotationsOff);
                        if (refList.is_err()) {
                            return Err(refList.unwrap_err());
                        }
                        for (ca::u32 setOff : refList.unwrap()->refList->annotationSetOffs) {
                            if (setOff != 0) {
                                Result<Entry*, WriteError> e = ensureSet(setOff);
                                if (e.is_err()) {
                                    return Err(e.unwrap_err());
                                }
                            }
                        }
                    } else {
                        Result<Entry*, WriteError> e = ensureSet(entry.annotationsOff);
                        if (e.is_err()) {
                            return Err(e.unwrap_err());
                        }
                    }
                }
            }
        }
        for (Entry& e : entries) {
            if (e.kind != Kind::AnnotationSet || e.set == nullptr) {
                continue;
            }
            for (ca::u32 itemOff : e.set->annotationOffs) {
                if (itemOff == 0) {
                    continue;
                }
                Result<Entry*, WriteError> ensured = ensureEntry(Kind::AnnotationItem, itemOff);
                if (ensured.is_err()) {
                    return Err(ensured.unwrap_err());
                }
                Entry* item = ensured.unwrap();
                if (item->oldLen == 0) {
                    Result<const AnnotationItem*, ReadError> parsed = dex.annotationItem(itemOff);
                    if (parsed.is_err() || parsed.unwrap() == nullptr) {
                        return Err(WriteError::SourceUnreadable);
                    }
                    item->oldLen = parsed.unwrap()->raw.length;
                    Result<void, WriteError> r = requireSpan(item->oldOff, item->oldLen);
                    if (r.is_err()) {
                        return Err(r.unwrap_err());
                    }
                }
            }
        }
    }

    // map 段逐项走查：引用闭包只能发现被目录/方法体指向的条目，而工具
    // （d8）会为"无注解"发射无人引用的空 annotation_set_item 等孤儿——
    // 段的 map 计数按条目总数声明。孤儿不入池则 no-edit 重建的 map size
    // 与 first 偏移漂移，checksum/signature 全变，破坏逐字节恒等承诺。
    // 六类自描述段按结构走查到段末；走查失败即段内布局不可靠，拒绝增量。
    // debug 段只在保留 debug 的场合走查：strip 语义是整段丢弃。
    std::vector<ca::u32> preservedOrphanKeys;
    {
        const auto sectionEndOf = [&](ca::usize mapIdx) -> ca::u32 {
            const ca::u32 nextOff =
                mapIdx + 1 < dex.mapItems.size() ? dex.mapItems[mapIdx + 1].offset
                                                 : static_cast<ca::u32>(source.size());
            return std::min(nextOff, static_cast<ca::u32>(source.size()));
        };
        const auto walkItems = [&](Kind kind, ca::usize mapIdx) -> Result<void, WriteError> {
            const MapItem& section = dex.mapItems[mapIdx];
            ca::u32 off = section.offset;
            const ca::u32 end = sectionEndOf(mapIdx);
            // map.size 是条目数声明；条目走完后段尾的对齐 padding 不属于
            // 任何条目，交给 gap 透传。
            for (ca::u32 seen = 0; seen < section.size; ++seen) {
                // 条目间对齐 padding（如 type_list 的 4 字节对齐）不属于
                // 任何条目，走查按 kind 对齐跳过；padding 落在条目间隙，
                // 由 gap 透传保留。
                off = alignUp(off, alignmentOf(kind));
                Result<Entry*, WriteError> ensured = ensureEntry(kind, off);
                if (ensured.is_err()) {
                    return Err(ensured.unwrap_err());
                }
                Entry* e = ensured.unwrap();
                ca::u32 len = e->oldLen;
                // oldLen==0 说明引用闭包没有发现它：这才是"源里就无人引用"
                // 的真孤儿；闭包发现过的条目生命周期仍由编辑语义决定。
                const bool closureFound = len != 0;
                if (len == 0) {
                    // 走查新发现的条目要连同内容一起入池（recompute 阶段
                    // 直接解引用 set/refList 等内容指针）。
                    Result<ca::u32, ReadError> parsed = itemLengthOf(dex, kind, off);
                    if (parsed.is_err() || parsed.unwrap() == 0) {
                        return Err(WriteError::NotIncremental);
                    }
                    len = parsed.unwrap();
                    // set/refList 的重编码会解引用内容指针；其余 kind 对源
                    // 条目是纯透传，只需 oldLen。
                    if (kind == Kind::AnnotationSet) {
                        auto set = dex.annotationSet(off);
                        if (set.is_err() || set.unwrap() == nullptr) {
                            return Err(WriteError::SourceUnreadable);
                        }
                        e->set = set.unwrap();
                    } else if (kind == Kind::AnnotationSetRefList) {
                        auto list = dex.annotationSetRefList(off);
                        if (list.is_err() || list.unwrap() == nullptr) {
                            return Err(WriteError::SourceUnreadable);
                        }
                        e->refList = list.unwrap();
                    }
                    e->oldLen = len;
                    Result<void, WriteError> r = requireSpan(off, len);
                    if (r.is_err()) {
                        return Err(r.unwrap_err());
                    }
                }
                if (len > end - off) {
                    return Err(WriteError::NotIncremental);
                }
                if (!closureFound) {
                    preservedOrphanKeys.push_back(off);
                }
                off += len;
            }
            return Ok();
        };
        for (ca::usize i = 0; i < dex.mapItems.size(); ++i) {
            switch (dex.mapItems[i].type) {
                case MapType::TypeList:
                case MapType::AnnotationSetItem:
                case MapType::AnnotationSetRefList:
                case MapType::AnnotationItem:
                case MapType::EncodedArrayItem:
                {
                    const std::optional<Kind> kind =
                        kindOfMapType(static_cast<ca::u32>(dex.mapItems[i].type));
                    if (!kind.has_value()) {
                        return Err(WriteError::InvalidModel);
                    }
                    Result<void, WriteError> r = walkItems(*kind, i);
                    if (r.is_err()) {
                        return Err(r.unwrap_err());
                    }
                    break;
                }
                case MapType::DebugInfoItem:
                    if (!options.stripDebugInfo) {
                        Result<void, WriteError> r = walkItems(Kind::DebugInfo, i);
                        if (r.is_err()) {
                            return Err(r.unwrap_err());
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }

    // 未建模 section：按原始区间透传。
    for (const RawSection& raw : dex.rawSections) {
        Entry e;
        e.kind = Kind::UnknownSection;
        e.rawMapType = raw.type;
        e.key = raw.span.offset;
        e.oldOff = raw.span.offset;
        e.oldLen = raw.span.length;
        if (raw.span.length != 0 && !covers(source, raw.span.offset, raw.span.length)) {
            return Err(WriteError::SourceUnreadable);
        }
        if (!options.keepUnknownSections) {
            e.removed = true;
        }
        addEntry(std::move(e));
    }

    // ---- 编辑计算（共享编辑层）----
    Result<MemberEditSet, WriteError> collectedEdits =
        collectMemberEdits(dex, options, classDataByOff);
    if (collectedEdits.is_err()) {
        return Err(collectedEdits.unwrap_err());
    }
    const MemberEditSet memberEdits = std::move(collectedEdits).unwrap();

    Result<AnnotationPlan, WriteError> planned =
        planAnnotations(dex, options, memberEdits, classDataByOff);
    if (planned.is_err()) {
        return Err(planned.unwrap_err());
    }
    const AnnotationPlan annotationPlan = std::move(planned).unwrap();

    const ca::u32 classCount = dex.classCount();

    // 逐类有效 class_data（源或注入副本，扣除删除、应用标志覆盖）。
    std::vector<ClassData> effectiveByClass(classCount);
    std::vector<bool> classDataContentChanged(classCount, false);
    for (ca::u32 i = 0; i < classCount; ++i) {
        const ClassData* sourceData = nullptr;
        const ca::u32 off = dex.classDefs[i].classDataOff;
        if (off != 0) {
            const auto found = classDataByOff.find(off);
            if (found == classDataByOff.end()) {
                return Err(WriteError::InvalidModel);
            }
            sourceData = found->second;
        }
        const auto edited = memberEdits.classDataEdits.find(i);
        effectiveByClass[i] = edited != memberEdits.classDataEdits.end()
                                  ? edited->second
                                  : (sourceData != nullptr ? *sourceData : ClassData{});
        const Result<void, WriteError> applied =
            applyMemberEdits(effectiveByClass[i], memberEdits);
        if (applied.is_err()) {
            return Err(applied.unwrap_err());
        }
        // 内容是否仍与源一致（不含 code_off）：决定 class_data 能否透传。
        bool changed = edited != memberEdits.classDataEdits.end();
        if (!changed && sourceData != nullptr) {
            const ClassData& eff = effectiveByClass[i];
            changed = eff.staticFields.size() != sourceData->staticFields.size() ||
                      eff.instanceFields.size() != sourceData->instanceFields.size() ||
                      eff.directMethods.size() != sourceData->directMethods.size() ||
                      eff.virtualMethods.size() != sourceData->virtualMethods.size();
            if (!changed) {
                for (ca::usize k = 0; k < eff.staticFields.size(); ++k) {
                    if (eff.staticFields[k].fieldIndex != sourceData->staticFields[k].fieldIndex ||
                        eff.staticFields[k].accessFlags !=
                            sourceData->staticFields[k].accessFlags) {
                        changed = true;
                        break;
                    }
                }
            }
            if (!changed) {
                for (ca::usize k = 0; k < eff.instanceFields.size(); ++k) {
                    if (eff.instanceFields[k].fieldIndex !=
                            sourceData->instanceFields[k].fieldIndex ||
                        eff.instanceFields[k].accessFlags !=
                            sourceData->instanceFields[k].accessFlags) {
                        changed = true;
                        break;
                    }
                }
            }
            if (!changed) {
                const std::vector<EncodedMethod>* effLists[2] = {&eff.directMethods,
                                                                 &eff.virtualMethods};
                const std::vector<EncodedMethod>* srcLists[2] = {&sourceData->directMethods,
                                                                 &sourceData->virtualMethods};
                for (int g = 0; !changed && g < 2; ++g) {
                    for (ca::usize k = 0; k < effLists[g]->size(); ++k) {
                        if ((*effLists[g])[k].methodIndex != (*srcLists[g])[k].methodIndex ||
                            (*effLists[g])[k].accessFlags != (*srcLists[g])[k].accessFlags) {
                            changed = true;
                            break;
                        }
                    }
                }
            }
        }
        classDataContentChanged[i] = changed;
    }

    // 逐类合成静态初值（nullopt = 沿用源数组）。
    std::vector<std::optional<EncodedArrayItem>> synthesizedValues(classCount);
    for (ca::u32 i = 0; i < classCount; ++i) {
        const ClassData* original = nullptr;
        const ca::u32 off = dex.classDefs[i].classDataOff;
        if (off != 0) {
            const auto found = classDataByOff.find(off);
            if (found == classDataByOff.end()) {
                return Err(WriteError::InvalidModel);
            }
            original = found->second;
        }
        std::vector<ca::u32> addedStatic;
        const auto bucket = memberEdits.fieldsByClass.find(i);
        if (bucket != memberEdits.fieldsByClass.end()) {
            for (const FieldAddition* add : bucket->second) {
                if (add->isStatic) {
                    addedStatic.push_back(add->fieldIdx);
                }
            }
        }
        Result<std::optional<EncodedArrayItem>, WriteError> synthesized = synthesizeStaticValues(
            dex, i, original, addedStatic, memberEdits, nullptr);
        if (synthesized.is_err()) {
            return Err(synthesized.unwrap_err());
        }
        synthesizedValues[i] = std::move(synthesized).unwrap();
    }

    // 注解目录键：覆盖类指向合成目录，全空则不引用。
    const auto annotationsKeyOf = [&](ca::u32 classDefIdx) -> ca::u32 {
        if (options.stripAnnotations) {
            return 0;
        }
        const EffectiveDirectory& eff = annotationPlan.dirs[classDefIdx];
        if (!eff.overridden) {
            return dex.classDefs[classDefIdx].annotationsOff;
        }
        return eff.effectivelyEmpty ? 0u : kOwnedDirectoryKeyBase + classDefIdx;
    };

    // ---- 编辑后引用集合：决定删除与新条目 ----
    std::unordered_set<ca::u32> referenced;
    const auto note = [&referenced](ca::u32 key) {
        if (key != 0) {
            referenced.insert(key);
        }
    };
    // 注入方法集合（其 code_off 是占位 1，发射时改指合成条目）。
    std::unordered_map<ca::u32, const MethodAddition*> addedMethodBodies;
    for (const auto& entry : memberEdits.methodsByClass) {
        for (const MethodAddition* add : entry.second) {
            addedMethodBodies.emplace(add->methodIdx, add);
        }
    }
    // 一个有效方法的 code 条目键：替换体/注入体走合成键，其余用源偏移。
    const auto codeKeyOfMethod = [&](const EncodedMethod& method) -> ca::u32 {
        if (method.codeOff == 0) {
            return 0;
        }
        if (memberEdits.replacements.count(method.methodIndex) != 0) {
            return kIncReplacedCodeKeyBase + method.methodIndex;
        }
        if (addedMethodBodies.count(method.methodIndex) != 0) {
            return kIncAddedCodeKeyBase + method.methodIndex;
        }
        return method.codeOff;
    };
    const auto interfaceKeyOf = [&](ca::u32 classDefIdx) -> ca::u32 {
        const ClassDef& def = dex.classDefs[classDefIdx];
        return def.ownedInterfaces ? kOwnedTypeListKeyBase + def.ownedInterfacesIdx
                                   : def.interfacesOff;
    };
    const auto classDataKeyOf = [&](ca::u32 classDefIdx) -> ca::u32 {
        if (memberEdits.classDataEdits.count(classDefIdx) != 0) {
            return kIncClassDataKeyBase + classDefIdx;
        }
        return dex.classDefs[classDefIdx].classDataOff;
    };
    const auto staticValuesKeyOf = [&](ca::u32 classDefIdx) -> ca::u32 {
        if (synthesizedValues[classDefIdx].has_value()) {
            return kIncArrayKeyBase + classDefIdx;
        }
        return dex.classDefs[classDefIdx].staticValuesOff;
    };

    for (ca::u32 i = 0; i < dex.stringCount(); ++i) {
        note(dex.stringIds[i].dataOff);
    }
    for (const ProtoId& proto : dex.protoIds) {
        note(proto.parametersOff);
    }
    for (ca::u32 i = 0; i < classCount; ++i) {
        const ClassDef& def = dex.classDefs[i];
        if (def.ownedInterfaces) {
            note(kOwnedTypeListKeyBase + def.ownedInterfacesIdx);
        } else {
            note(def.interfacesOff);
        }
        note(annotationsKeyOf(i));
        if (memberEdits.classDataEdits.count(i) != 0) {
            note(kIncClassDataKeyBase + i);
        } else {
            note(def.classDataOff);
        }
        if (synthesizedValues[i].has_value()) {
            note(kIncArrayKeyBase + i);
        } else {
            note(def.staticValuesOff);
        }
        const ClassData& eff = effectiveByClass[i];
        const std::vector<EncodedMethod>* lists[2] = {&eff.directMethods, &eff.virtualMethods};
        for (const std::vector<EncodedMethod>* list : lists) {
            for (const EncodedMethod& method : *list) {
                const ca::u32 key = codeKeyOfMethod(method);
                note(key);
                const CodeItem* item = nullptr;
                if (key == kIncReplacedCodeKeyBase + method.methodIndex) {
                    item = &memberEdits.replacements.find(method.methodIndex)->second->item;
                } else if (key == kIncAddedCodeKeyBase + method.methodIndex) {
                    item = &addedMethodBodies[method.methodIndex]->item;
                } else {
                    const Entry* e = entryAt(key);
                    item = e != nullptr ? e->code : nullptr;
                }
                if (!options.stripDebugInfo && item != nullptr && item->debugInfoOff != 0) {
                    note(item->debugInfoOff);
                }
            }
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        note(site.callSiteOff);
    }
    // 注解：生效目录引用的 set/ref_list 与 item（源偏移或合成键）。
    {
        std::set<ca::u32> setKeys;
        std::set<ca::u32> refListKeys;
        for (const EffectiveDirectory& eff : annotationPlan.dirs) {
            if (eff.content.classAnnotationsOff != 0) {
                setKeys.insert(eff.content.classAnnotationsOff);
            }
            for (const AnnotationsDirectoryEntry& e : eff.content.fieldAnnotations) {
                if (e.annotationsOff != 0) {
                    setKeys.insert(e.annotationsOff);
                }
            }
            for (const AnnotationsDirectoryEntry& e : eff.content.methodAnnotations) {
                if (e.annotationsOff != 0) {
                    setKeys.insert(e.annotationsOff);
                }
            }
            for (const AnnotationsDirectoryEntry& e : eff.content.parameterAnnotations) {
                if (e.annotationsOff != 0) {
                    refListKeys.insert(e.annotationsOff);
                }
            }
        }
        for (ca::u32 key : refListKeys) {
            if (key < kSourceOffsetLimit) {
                const Entry* e = entryAt(key);
                if (e == nullptr) {
                    return Err(WriteError::InvalidModel);
                }
                for (ca::u32 setOff : e->refList->annotationSetOffs) {
                    if (setOff != 0) {
                        setKeys.insert(setOff);
                    }
                }
            }
        }
        for (ca::u32 key : setKeys) {
            if (key < kSourceOffsetLimit) {
                const Entry* e = entryAt(key);
                if (e == nullptr) {
                    return Err(WriteError::InvalidModel);
                }
                for (ca::u32 itemOff : e->set->annotationOffs) {
                    if (itemOff != 0) {
                        note(itemOff);
                    }
                }
            }
            note(key);
        }
        for (const auto& entry : annotationPlan.ownedSetItems) {
            note(entry.first);
            for (ca::u32 handle : *entry.second) {
                note(kOwnedItemKeyBase + handle);
            }
        }
        for (const auto& entry : annotationPlan.ownedRefListSets) {
            note(entry.first);
        }
    }

    // 孤儿条目（map 段走查发现、无引用者）无条件保留：它们对语义不可见，
    // 删除只会破坏 map 计数与 no-edit 字节恒等；strip debug 的孤儿已在
    // 走查阶段按编辑语义跳过。
    for (ca::u32 key : preservedOrphanKeys) {
        referenced.insert(key);
    }

    // 数据条目不在编辑后引用集合内 → 删除（表与固定区除外）。
    for (Entry& e : entries) {
        if (e.removed) {
            continue;
        }
        switch (e.kind) {
            case Kind::StringData:
            case Kind::TypeList:
            case Kind::EncodedArray:
            case Kind::AnnotationItem:
            case Kind::AnnotationSet:
            case Kind::AnnotationSetRefList:
            case Kind::AnnotationsDirectory:
            case Kind::DebugInfo:
            case Kind::CodeItem:
            case Kind::ClassData:
                if (referenced.count(e.key) == 0) {
                    e.removed = true;
                }
                break;
            default:
                break;
        }
    }

    // ---- 合成条目：referenced 中的合成键各建一条 ----
    std::vector<Entry> synthetic;
    for (ca::u32 key : referenced) {
        if (key < kSourceOffsetLimit) {
            continue;
        }
        Entry e;
        e.synthetic = true;
        e.key = key;
        if (key >= kIncReplacedCodeKeyBase && key < kIncAddedCodeKeyBase) {
            const auto repl = memberEdits.replacements.find(key - kIncReplacedCodeKeyBase);
            if (repl == memberEdits.replacements.end()) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::CodeItem;
            e.replacement = repl->second;
        } else if (key >= kIncAddedCodeKeyBase && key < kIncClassDataKeyBase) {
            const auto add = addedMethodBodies.find(key - kIncAddedCodeKeyBase);
            if (add == addedMethodBodies.end()) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::CodeItem;
            e.addition = add->second;
        } else if (key >= kIncClassDataKeyBase && key < kIncArrayKeyBase) {
            const ca::u32 classDefIdx = key - kIncClassDataKeyBase;
            if (classDefIdx >= classCount) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::ClassData;
            e.effectiveClassData = &effectiveByClass[classDefIdx];
        } else if (key >= kIncArrayKeyBase && key < kOwnedTypeListKeyBase) {
            const ca::u32 classDefIdx = key - kIncArrayKeyBase;
            if (!synthesizedValues[classDefIdx].has_value()) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::EncodedArray;
            Result<std::vector<ca::u8>, WriteError> encoded =
                writeEncodedArrayItem(*synthesizedValues[classDefIdx]);
            if (encoded.is_err()) {
                return Err(encoded.unwrap_err());
            }
            e.constantBytes = std::move(encoded).unwrap();
        } else if (key >= kOwnedTypeListKeyBase && key < kOwnedItemKeyBase) {
            e.kind = Kind::TypeList;
            e.ownedTypeListIdx = key - kOwnedTypeListKeyBase;
            const TypeListSpan span = dex.ownedTypeListSpan(e.ownedTypeListIdx);
            if (span.entries == nullptr) {
                return Err(WriteError::InvalidModel);
            }
            std::vector<ca::u8> bytes;
            appendU32(bytes, span.size);
            for (ca::u32 j = 0; j < span.size; ++j) {
                const ca::u32 typeIdx = span.at(j);
                if (typeIdx >= dex.typeCount()) {
                    return Err(WriteError::InvalidModel);
                }
                appendU16(bytes, static_cast<ca::u16>(typeIdx));
            }
            e.constantBytes = std::move(bytes);
        } else if (key >= kOwnedItemKeyBase && key < kOwnedSetKeyBase) {
            const AnnotationItem* item = dex.ownedAnnotationItem(key - kOwnedItemKeyBase);
            if (item == nullptr) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::AnnotationItem;
            Result<std::vector<ca::u8>, WriteError> encoded = writeAnnotationItem(*item);
            if (encoded.is_err()) {
                return Err(encoded.unwrap_err());
            }
            e.constantBytes = std::move(encoded).unwrap();
        } else if (key >= kOwnedSetKeyBase && key < kOwnedRefListKeyBase) {
            const auto set = annotationPlan.ownedSetItems.find(key);
            if (set == annotationPlan.ownedSetItems.end()) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::AnnotationSet;
            e.ownedSetItems = *set->second;
        } else if (key >= kOwnedRefListKeyBase && key < kOwnedDirectoryKeyBase) {
            const auto list = annotationPlan.ownedRefListSets.find(key);
            if (list == annotationPlan.ownedRefListSets.end()) {
                return Err(WriteError::InvalidModel);
            }
            e.kind = Kind::AnnotationSetRefList;
            e.ownedRefListSets = list->second;
        } else if (key >= kOwnedDirectoryKeyBase) {
            const ca::u32 classDefIdx = key - kOwnedDirectoryKeyBase;
            if (classDefIdx >= classCount) {
                return Err(WriteError::InvalidModel);
            }
            const EffectiveDirectory& eff = annotationPlan.dirs[classDefIdx];
            e.kind = Kind::AnnotationsDirectory;
            e.directoryClassSetKey = eff.content.classAnnotationsOff;
            e.directoryFields = &eff.content.fieldAnnotations;
            e.directoryMethods = &eff.content.methodAnnotations;
            e.directoryParameters = &eff.content.parameterAnnotations;
        } else {
            return Err(WriteError::InvalidModel);
        }
        synthetic.push_back(std::move(e));
    }

    // 合成条目锚定：同 kind 源组尾（无源组则 map_list 前，按 map type 排序）。
    std::map<Kind, ca::u32> lastSourceOffByKind;
    for (const Entry& e : entries) {
        if (!e.synthetic) {
            lastSourceOffByKind[e.kind] =
                std::max(lastSourceOffByKind.count(e.kind) != 0 ? lastSourceOffByKind[e.kind]
                                                                 : 0u,
                         e.oldOff + e.oldLen);
        }
    }
    for (Entry& e : synthetic) {
        const auto anchor = lastSourceOffByKind.find(e.kind);
        e.oldOff = anchor != lastSourceOffByKind.end() ? anchor->second : header.mapOff;
    }

    // 排序：源序 + 合成条目紧贴锚点；同锚按 map type、键升序。
    entries.insert(entries.end(), std::make_move_iterator(synthetic.begin()),
                   std::make_move_iterator(synthetic.end()));
    const ca::u32 tailAnchor = header.mapOff;
    std::stable_sort(entries.begin(), entries.end(),
                     [tailAnchor](const Entry& a, const Entry& b) {
                         return a.sortKey(tailAnchor) < b.sortKey(tailAnchor);
                     });
    // 排序移动了元素，按键索引需要重建，之后的 entryAt 才能继续命中。
    entryIndexByKey.clear();
    for (ca::usize i = 0; i < entries.size(); ++i) {
        entryIndexByKey.emplace(entries[i].key, i);
    }

    // 源条目必须互不重叠（重叠说明发现自相矛盾）。
    {
        ca::u32 prevEnd = 0;
        for (const Entry& e : entries) {
            if (e.synthetic) {
                continue;
            }
            if (e.oldOff < prevEnd) {
                return Err(WriteError::SourceUnreadable);
            }
            prevEnd = e.oldOff + e.oldLen;
        }
    }
    // 保留条目按 map type 必须连续：同 type 条目被其他 section 隔开时，
    // map_list 的 (offset, size) 无法如实描述该组。
    {
        std::set<ca::u32> seen;
        ca::u32 last = 0xFFFFFFFFu;
        for (const Entry& e : entries) {
            if (e.removed || e.kind == Kind::Header) {
                continue;
            }
            const ca::u32 type = mapTypeOf(e.kind, e.rawMapType);
            if (type != last) {
                if (!seen.insert(type).second) {
                    return Err(WriteError::SourceUnreadable);
                }
                last = type;
            }
        }
    }

    // 源 class_data 条目的引用类（共享去重；编辑类走合成条目）。
    for (ca::u32 i = 0; i < classCount; ++i) {
        const ca::u32 key = classDataKeyOf(i);
        if (key == 0 || key >= kSourceOffsetLimit) {
            continue;
        }
        if (Entry* e = entryAt(key); e != nullptr) {
            e->users.push_back(i);
        }
    }

    // map 组计数：定长表的 size 是表内条目数（不是发射条目数）；条目集合
    // 在编辑定档后固定，map_list 长度随之固定。
    std::map<ca::u32, ca::u32> groupCounts;
    const auto mapCountOf = [&](const Entry& e) -> ca::u32 {
        switch (e.kind) {
            case Kind::StringIds: return header.stringIdsSize;
            case Kind::TypeIds: return header.typeIdsSize;
            case Kind::ProtoIds: return header.protoIdsSize;
            case Kind::FieldIds: return header.fieldIdsSize;
            case Kind::MethodIds: return header.methodIdsSize;
            case Kind::ClassDefs: return classCount;
            case Kind::CallSites: return dex.callSiteCount();
            case Kind::MethodHandles: return dex.methodHandleCount();
            default: return 1u;
        }
    };
    for (const Entry& e : entries) {
        if (!e.removed && e.kind != Kind::Header && e.kind != Kind::MapList) {
            groupCounts[mapTypeOf(e.kind, e.rawMapType)] += mapCountOf(e);
        }
    }
    const ca::u32 mapLen = static_cast<ca::u32>(4u + (groupCounts.size() + 2u) * 12u);

    // ---- 迭代布局：重编码 → 分配新偏移 → 建立映射，直到条目形态稳定 ----
    OffsetMap offsets;
    offsets.resetIdentity(static_cast<ca::u32>(source.size()));
    for (const Entry& e : entries) {
        if (e.synthetic) {
            offsets.addKey(e.key, e.key);  // 首轮自映射，避免引用悬垂误报
        }
    }

    // 有效 class_data 的重编码：code_off 回填到当前映射 + 组内索引排序。
    const auto encodeEffectiveClassData = [&](const ClassData& src, const auto& resolve)
        -> Result<std::vector<ca::u8>, WriteError> {
        ClassData copy = src;
        for (std::vector<EncodedMethod>* list : {&copy.directMethods, &copy.virtualMethods}) {
            for (EncodedMethod& method : *list) {
                if (method.codeOff == 0) {
                    continue;
                }
                const Result<ca::u32, WriteError> v = resolve(codeKeyOfMethod(method));
                if (v.is_err()) {
                    return Err(v.unwrap_err());
                }
            }
            std::sort(list->begin(), list->end(),
                      [](const EncodedMethod& a, const EncodedMethod& b) {
                          return a.methodIndex < b.methodIndex;
                      });
        }
        for (std::vector<EncodedField>* list : {&copy.staticFields, &copy.instanceFields}) {
            std::sort(list->begin(), list->end(),
                      [](const EncodedField& a, const EncodedField& b) {
                          return a.fieldIndex < b.fieldIndex;
                      });
        }
        return writeClassData(copy);
    };

    // 每轮重算一个条目：引用偏移全部未变则透传源字节，否则重编码/重发射。
    const auto recomputeEntry = [&](Entry& e) -> Result<void, WriteError> {
        if (e.removed) {
            return Ok();
        }
        const auto resolve = [&offsets](ca::u32 key) -> Result<ca::u32, WriteError> {
            const ca::u32 v = offsets.resolve(key);
            if (v == OffsetMap::kDangling) {
                return Err(WriteError::InvalidModel);
            }
            return Ok(v);
        };
        // 解析并检查「映射后 == 源值」：悬垂返回 kDangling，调用方判 !ok。
        const auto resolveSame = [&offsets](ca::u32 key, bool* ok) {
            const ca::u32 v = offsets.resolve(key);
            *ok = v != OffsetMap::kDangling;
            return v;
        };
        switch (e.kind) {
            case Kind::Header:
            case Kind::TypeIds:
            case Kind::FieldIds:
            case Kind::MethodIds:
            case Kind::MethodHandles:
            case Kind::UnknownSection:
            case Kind::StringData:
            case Kind::DebugInfo:
            case Kind::MapList:
                e.passthrough = true;
                return Ok();
            case Kind::TypeList:
            case Kind::AnnotationItem:
            case Kind::EncodedArray: {
                if (!e.synthetic) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded = e.constantBytes;  // 内容只含不变的表索引
                return Ok();
            }
            case Kind::StringIds: {
                bool same = true;
                for (const StringId& id : dex.stringIds) {
                    bool ok = true;
                    if (resolveSame(id.dataOff, &ok) != id.dataOff || !ok) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded.clear();
                for (const StringId& id : dex.stringIds) {
                    const Result<ca::u32, WriteError> v = resolve(id.dataOff);
                    if (v.is_err()) {
                        return Err(v.unwrap_err());
                    }
                    appendU32(e.encoded, v.unwrap());
                }
                return Ok();
            }
            case Kind::ProtoIds: {
                bool same = true;
                for (const ProtoId& proto : dex.protoIds) {
                    if (proto.parametersOff == 0) {
                        continue;
                    }
                    bool ok = true;
                    if (resolveSame(proto.parametersOff, &ok) != proto.parametersOff || !ok) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded.clear();
                for (const ProtoId& proto : dex.protoIds) {
                    const Result<ca::u32, WriteError> v = resolve(proto.parametersOff);
                    if (v.is_err()) {
                        return Err(v.unwrap_err());
                    }
                    appendU32(e.encoded, proto.shortyIdx);
                    appendU32(e.encoded, proto.returnTypeIdx);
                    appendU32(e.encoded, v.unwrap());
                }
                return Ok();
            }
            case Kind::ClassDefs: {
                bool same = dex.classDefs.size() == srcDefs.size();
                for (ca::u32 i = 0; same && i < classCount; ++i) {
                    const ClassDef& def = dex.classDefs[i];
                    const SourceClassDef& src = srcDefs[i];
                    if (def.classIdx != src.classIdx || def.accessFlags != src.accessFlags ||
                        def.superclassIdx != src.superclassIdx ||
                        def.sourceFileIdx != src.sourceFileIdx) {
                        same = false;
                        break;
                    }
                    const ca::u32 keys[4] = {interfaceKeyOf(i), annotationsKeyOf(i),
                                             classDataKeyOf(i), staticValuesKeyOf(i)};
                    const ca::u32 srcKeys[4] = {src.interfacesOff, src.annotationsOff,
                                                src.classDataOff, src.staticValuesOff};
                    for (int k = 0; same && k < 4; ++k) {
                        if (keys[k] != srcKeys[k]) {
                            same = false;
                            break;
                        }
                        bool ok = true;
                        if (resolveSame(keys[k], &ok) != keys[k] || !ok) {
                            same = false;
                        }
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded.clear();
                for (ca::u32 i = 0; i < classCount; ++i) {
                    const ClassDef& def = dex.classDefs[i];
                    const Result<ca::u32, WriteError> interfaces = resolve(interfaceKeyOf(i));
                    const Result<ca::u32, WriteError> annotations = resolve(annotationsKeyOf(i));
                    const Result<ca::u32, WriteError> classData = resolve(classDataKeyOf(i));
                    const Result<ca::u32, WriteError> staticValues =
                        resolve(staticValuesKeyOf(i));
                    if (interfaces.is_err() || annotations.is_err() || classData.is_err() ||
                        staticValues.is_err()) {
                        return Err(WriteError::InvalidModel);
                    }
                    appendU32(e.encoded, def.classIdx);
                    appendU32(e.encoded, def.accessFlags);
                    appendU32(e.encoded, def.superclassIdx);
                    appendU32(e.encoded, interfaces.unwrap());
                    appendU32(e.encoded, def.sourceFileIdx);
                    appendU32(e.encoded, annotations.unwrap());
                    appendU32(e.encoded, classData.unwrap());
                    appendU32(e.encoded, staticValues.unwrap());
                }
                return Ok();
            }
            case Kind::CallSites: {
                bool same = true;
                for (const CallSiteId& site : dex.callSites) {
                    bool ok = true;
                    if (resolveSame(site.callSiteOff, &ok) != site.callSiteOff || !ok) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded.clear();
                for (const CallSiteId& site : dex.callSites) {
                    const Result<ca::u32, WriteError> v = resolve(site.callSiteOff);
                    if (v.is_err()) {
                        return Err(v.unwrap_err());
                    }
                    appendU32(e.encoded, v.unwrap());
                }
                return Ok();
            }
            case Kind::AnnotationSet: {
                e.passthrough = false;
                e.encoded.clear();
                if (e.synthetic) {
                    appendU32(e.encoded, static_cast<ca::u32>(e.ownedSetItems.size()));
                    for (ca::u32 handle : e.ownedSetItems) {
                        const Result<ca::u32, WriteError> v =
                            resolve(kOwnedItemKeyBase + handle);
                        if (v.is_err()) {
                            return Err(v.unwrap_err());
                        }
                        appendU32(e.encoded, v.unwrap());
                    }
                    return Ok();
                }
                bool same = true;
                for (ca::u32 off : e.set->annotationOffs) {
                    if (off == 0) {
                        continue;
                    }
                    bool ok = true;
                    if (resolveSame(off, &ok) != off || !ok) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                appendU32(e.encoded, static_cast<ca::u32>(e.set->annotationOffs.size()));
                for (ca::u32 off : e.set->annotationOffs) {
                    const Result<ca::u32, WriteError> v = resolve(off);
                    if (v.is_err()) {
                        return Err(v.unwrap_err());
                    }
                    appendU32(e.encoded, v.unwrap());
                }
                return Ok();
            }
            case Kind::AnnotationSetRefList: {
                e.passthrough = false;
                e.encoded.clear();
                if (e.synthetic) {
                    appendU32(e.encoded, static_cast<ca::u32>(e.ownedRefListSets.size()));
                    for (ca::u32 setKey : e.ownedRefListSets) {
                        if (setKey == 0) {
                            appendU32(e.encoded, 0);
                            continue;
                        }
                        const Result<ca::u32, WriteError> v = resolve(setKey);
                        if (v.is_err()) {
                            return Err(v.unwrap_err());
                        }
                        appendU32(e.encoded, v.unwrap());
                    }
                    return Ok();
                }
                bool same = true;
                for (ca::u32 off : e.refList->annotationSetOffs) {
                    if (off == 0) {
                        continue;
                    }
                    bool ok = true;
                    if (resolveSame(off, &ok) != off || !ok) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                appendU32(e.encoded, static_cast<ca::u32>(e.refList->annotationSetOffs.size()));
                for (ca::u32 off : e.refList->annotationSetOffs) {
                    const Result<ca::u32, WriteError> v = resolve(off);
                    if (v.is_err()) {
                        return Err(v.unwrap_err());
                    }
                    appendU32(e.encoded, v.unwrap());
                }
                return Ok();
            }
            case Kind::AnnotationsDirectory: {
                bool syntheticDir = e.synthetic;
                bool same = !syntheticDir;
                const AnnotationsDirectory* content = e.directory;
                if (syntheticDir) {
                    content = nullptr;  // 合成目录的内容在下面的指针组里
                }
                const std::vector<AnnotationsDirectoryEntry>* srcGroups[3] = {
                    content == nullptr ? nullptr : &content->fieldAnnotations,
                    content == nullptr ? nullptr : &content->methodAnnotations,
                    content == nullptr ? nullptr : &content->parameterAnnotations};
                const std::vector<AnnotationsDirectoryEntry>* entryGroups[3] = {
                    e.directoryFields, e.directoryMethods, e.directoryParameters};
                const ca::u32 classSetKey =
                    syntheticDir ? e.directoryClassSetKey
                                 : (content != nullptr ? content->classAnnotationsOff : 0);
                if (same) {
                    bool ok = true;
                    if (classSetKey != 0 &&
                        (resolveSame(classSetKey, &ok) != classSetKey || !ok)) {
                        same = false;
                    }
                    for (const std::vector<AnnotationsDirectoryEntry>* group : srcGroups) {
                        if (!same) {
                            break;
                        }
                        for (const AnnotationsDirectoryEntry& entry : *group) {
                            if (entry.annotationsOff == 0) {
                                continue;
                            }
                            bool entryOk = true;
                            if (resolveSame(entry.annotationsOff, &entryOk) !=
                                    entry.annotationsOff ||
                                !entryOk) {
                                same = false;
                                break;
                            }
                        }
                    }
                }
                if (same && !syntheticDir) {
                    e.passthrough = true;
                    return Ok();
                }
                e.passthrough = false;
                e.encoded.clear();
                if (classSetKey == 0) {
                    appendU32(e.encoded, 0);
                } else {
                    const Result<ca::u32, WriteError> classSet = resolve(classSetKey);
                    if (classSet.is_err()) {
                        return Err(classSet.unwrap_err());
                    }
                    appendU32(e.encoded, classSet.unwrap());
                }
                for (int g = 0; g < 3; ++g) {
                    const std::vector<AnnotationsDirectoryEntry>* group =
                        syntheticDir ? entryGroups[g] : srcGroups[g];
                    appendU32(e.encoded, static_cast<ca::u32>(group->size()));
                    for (const AnnotationsDirectoryEntry& entry : *group) {
                        if (entry.annotationsOff == 0) {
                            appendU32(e.encoded, entry.memberIdx);
                            appendU32(e.encoded, 0);
                            continue;
                        }
                        const Result<ca::u32, WriteError> v = resolve(entry.annotationsOff);
                        if (v.is_err()) {
                            return Err(v.unwrap_err());
                        }
                        appendU32(e.encoded, entry.memberIdx);
                        appendU32(e.encoded, v.unwrap());
                    }
                }
                return Ok();
            }
            case Kind::CodeItem: {
                if (e.synthetic) {
                    const CodeItem* src =
                        e.replacement != nullptr ? &e.replacement->item : &e.addition->item;
                    const ByteSlice insns =
                        e.replacement != nullptr
                            ? ByteSlice{e.replacement->insns.data(),
                                        e.replacement->insns.size()}
                            : ByteSlice{e.addition->insns.data(),
                                        e.addition->insns.size()};
                    CodeItem copy = *src;
                    if (options.stripDebugInfo || src->debugInfoOff == 0) {
                        copy.debugInfoOff = 0;
                    } else {
                        const Result<ca::u32, WriteError> debug = resolve(src->debugInfoOff);
                        if (debug.is_err()) {
                            return Err(debug.unwrap_err());
                        }
                        copy.debugInfoOff = debug.unwrap();
                    }
                    Result<std::vector<ca::u8>, WriteError> encoded = writeCodeItem(copy, insns);
                    if (encoded.is_err()) {
                        return Err(encoded.unwrap_err());
                    }
                    e.passthrough = false;
                    e.encoded = std::move(encoded).unwrap();
                    return Ok();
                }
                const ca::u32 srcDebug = e.code->debugInfoOff;
                if (options.stripDebugInfo || srcDebug == 0) {
                    if (!options.stripDebugInfo || srcDebug == 0) {
                        e.passthrough = true;
                        return Ok();
                    }
                    // strip：debug_info_off 归零，其余源字节照抄。
                    e.passthrough = false;
                    e.encoded.assign(source.data() + e.oldOff,
                                     source.data() + e.oldOff + e.oldLen);
                    putU32(e.encoded, 8, 0);  // 头部第 8 字节起是 debug_info_off
                    return Ok();
                }
                const Result<ca::u32, WriteError> debug = resolve(srcDebug);
                if (debug.is_err()) {
                    return Err(debug.unwrap_err());
                }
                if (debug.unwrap() == srcDebug) {
                    e.passthrough = true;
                    return Ok();
                }
                // 只有头部 debug_info_off 变化：拷源字节原地补 4 字节，
                // 避免 insns/tries/handlers 的整段重编码。
                e.passthrough = false;
                e.encoded.assign(source.data() + e.oldOff,
                                 source.data() + e.oldOff + e.oldLen);
                putU32(e.encoded, 8, debug.unwrap());  // 头部第 8 字节起
                return Ok();
            }
            case Kind::ClassData: {
                if (e.synthetic) {
                    Result<std::vector<ca::u8>, WriteError> encoded =
                        encodeEffectiveClassData(*e.effectiveClassData, resolve);
                    if (encoded.is_err()) {
                        return Err(encoded.unwrap_err());
                    }
                    e.passthrough = false;
                    e.encoded = std::move(encoded).unwrap();
                    return Ok();
                }
                // 共享条目：所有引用类的内容未变且 code 键映射不变才透传。
                bool same = true;
                for (ca::u32 classDefIdx : e.users) {
                    if (classDataContentChanged[classDefIdx]) {
                        same = false;
                        break;
                    }
                    const ClassData& eff = effectiveByClass[classDefIdx];
                    const std::vector<EncodedMethod>* lists[2] = {&eff.directMethods,
                                                                 &eff.virtualMethods};
                    for (const std::vector<EncodedMethod>* list : lists) {
                        if (!same) {
                            break;
                        }
                        for (const EncodedMethod& method : *list) {
                            if (method.codeOff == 0) {
                                continue;
                            }
                            const ca::u32 key = codeKeyOfMethod(method);
                            bool ok = true;
                            if (key != method.codeOff ||
                                resolveSame(key, &ok) != method.codeOff || !ok) {
                                same = false;
                                break;
                            }
                        }
                    }
                }
                if (same) {
                    e.passthrough = true;
                    return Ok();
                }
                if (e.users.empty()) {
                    return Err(WriteError::InvalidModel);
                }
                Result<std::vector<ca::u8>, WriteError> encoded =
                    encodeEffectiveClassData(effectiveByClass[e.users.front()], resolve);
                if (encoded.is_err()) {
                    return Err(encoded.unwrap_err());
                }
                e.passthrough = false;
                e.encoded = std::move(encoded).unwrap();
                return Ok();
            }
        }
        return Ok();
    };

    // 布局扫描：按源序分配 newOff，记录 gap 映射与对齐补零。
    struct PassState
    {
        bool passthrough = true;
        ca::u32 len = 0;
    };
    std::vector<PassState> previous(entries.size());
    std::vector<ca::u32> pads(entries.size(), 0);
    ca::u32 total = 0;
    const ca::u32 fileSize = static_cast<ca::u32>(source.size());
    bool converged = false;
    for (ca::u32 pass = 0; pass < kMaxLayoutPasses && !converged; ++pass) {
        for (Entry& e : entries) {
            const Result<void, WriteError> r = recomputeEntry(e);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
        offsets.resetIdentity(fileSize);
        ca::u32 cursor = 0;
        ca::u32 prevEnd = 0;
        bool sameAsPrevious = pass > 0;
        for (ca::usize idx = 0; idx < entries.size(); ++idx) {
            Entry& e = entries[idx];
            if (!e.synthetic) {
                const ca::u32 gap = e.oldOff - prevEnd;
                if (gap != 0) {
                    offsets.addSegment(prevEnd, gap, cursor);
                    cursor += gap;
                }
                prevEnd = e.oldOff + e.oldLen;
            }
            pads[idx] = 0;
            if (e.removed) {
                continue;
            }
            const ca::u32 want = alignmentOf(e.kind);
            const ca::u32 align = !e.synthetic && (e.oldOff % want) != 0 ? 1u : want;
            pads[idx] = alignUp(cursor, align) - cursor;
            cursor += pads[idx];
            e.newOff = cursor;
            const ca::u32 len = e.kind == Kind::MapList ? mapLen : e.len();
            cursor += len;
            if (e.synthetic) {
                offsets.addKey(e.key, e.newOff);
            } else {
                offsets.addSegment(e.oldOff, e.oldLen, e.newOff);
            }
            const PassState current{e.passthrough, len};
            if (current.passthrough != previous[idx].passthrough ||
                current.len != previous[idx].len) {
                sameAsPrevious = false;
            }
            previous[idx] = current;
        }
        offsets.sortSegments();
        total = cursor;
        converged = sameAsPrevious;
    }
    if (!converged) {
        return Err(WriteError::Unencodable);  // ULEB 宽度反馈未收敛（病态布局）
    }

    // ---- 发射：透传/重编码条目 + gap + 对齐补零 + map_list + header ----
    std::vector<ca::u8> out(total, 0);
    {
        ca::u32 cursor = 0;
        ca::u32 prevEnd = 0;
        const Entry* mapEntry = nullptr;
        const auto appendSpan = [&out, &cursor](const ca::u8* data, ca::u32 len) {
            if (len != 0) {
                std::memcpy(out.data() + cursor, data, len);
                cursor += len;
            }
        };
        for (ca::usize idx = 0; idx < entries.size(); ++idx) {
            const Entry& e = entries[idx];
            if (!e.synthetic) {
                const ca::u32 gap = e.oldOff - prevEnd;
                if (gap != 0) {
                    appendSpan(source.data() + prevEnd, gap);  // gap 原字节透传
                }
                prevEnd = e.oldOff + e.oldLen;
            }
            if (e.removed) {
                continue;
            }
            cursor += pads[idx];  // 对齐补零（out 已零初始化）
            const ca::u32 len = e.kind == Kind::MapList ? mapLen : e.len();
            if (e.kind == Kind::MapList) {
                mapEntry = &e;
                cursor += len;
            } else if (e.passthrough) {
                appendSpan(source.data() + e.oldOff, e.oldLen);
            } else {
                appendSpan(e.encoded.data(), static_cast<ca::u32>(e.encoded.size()));
            }
        }
        if (const ca::u32 tailGap = fileSize - prevEnd; tailGap != 0) {
            appendSpan(source.data() + prevEnd, tailGap);
        }
        if (mapEntry == nullptr) {
            return Err(WriteError::InvalidModel);
        }

        // map_list：聚合保留条目按组首偏移排序；unused 沿用源条目。
        std::map<ca::u32, ca::u16> mapUnused;
        for (const MapItem& item : dex.mapItems) {
            mapUnused[static_cast<ca::u32>(item.type)] = item.unused;
        }
        struct Group
        {
            ca::u32 type = 0;
            ca::u32 count = 0;
            ca::u32 first = 0;
            ca::u16 unused = 0;
        };
        std::vector<Group> groups;
        const auto unusedOf = [&mapUnused](ca::u32 type) -> ca::u16 {
            const auto it = mapUnused.find(type);
            return it == mapUnused.end() ? ca::u16{0} : it->second;
        };
        groups.push_back(Group{static_cast<ca::u32>(MapType::HeaderItem), 1, 0,
                               unusedOf(static_cast<ca::u32>(MapType::HeaderItem))});
        groups.push_back(Group{static_cast<ca::u32>(MapType::MapList), 1, mapEntry->newOff,
                               unusedOf(static_cast<ca::u32>(MapType::MapList))});
        for (const auto& [type, count] : groupCounts) {
            ca::u32 first = 0xFFFFFFFFu;
            for (const Entry& e : entries) {
                if (!e.removed && e.kind != Kind::Header && e.kind != Kind::MapList &&
                    mapTypeOf(e.kind, e.rawMapType) == type) {
                    first = std::min(first, e.newOff);
                }
            }
            if (first == 0xFFFFFFFFu) {
                return Err(WriteError::InvalidModel);
            }
            groups.push_back(Group{type, count, first, unusedOf(type)});
        }
        std::sort(groups.begin(), groups.end(),
                  [](const Group& a, const Group& b) { return a.first < b.first; });
        std::vector<ca::u8> mapBytes;
        appendU32(mapBytes, static_cast<ca::u32>(groups.size()));
        for (const Group& group : groups) {
            appendU16(mapBytes, static_cast<ca::u16>(group.type));
            appendU16(mapBytes, group.unused);
            appendU32(mapBytes, group.count);
            appendU32(mapBytes, group.first);
        }
        if (mapBytes.size() != mapLen) {
            return Err(WriteError::InvalidModel);
        }
        std::memcpy(out.data() + mapEntry->newOff, mapBytes.data(), mapBytes.size());

        // header：透传源 0x70 字节后回填变化字段。
        std::memcpy(out.data(), source.data(), kHeaderSize);
        const auto tableOffsetOf = [&](Kind kind) -> ca::u32 {
            for (const Entry& e : entries) {
                if (!e.removed && !e.synthetic && e.kind == kind) {
                    return e.newOff;
                }
            }
            return 0;  // 空表：保留源值（透传 header 已含）
        };
        putU32(out, 32, total);
        putU32(out, 52, mapEntry->newOff);
        putU32(out, 60, tableOffsetOf(Kind::StringIds));
        putU32(out, 68, tableOffsetOf(Kind::TypeIds));
        putU32(out, 76, tableOffsetOf(Kind::ProtoIds));
        putU32(out, 84, tableOffsetOf(Kind::FieldIds));
        putU32(out, 92, tableOffsetOf(Kind::MethodIds));
        putU32(out, 96, classCount);
        putU32(out, 100, tableOffsetOf(Kind::ClassDefs));
        // data_off 按宿主平移；宿主不可寻（病态源）时退回表尾对齐。
        ca::u32 dataOff = offsets.resolve(header.dataOff);
        if (dataOff == OffsetMap::kDangling || header.dataOff == 0) {
            ca::u32 tableEnd = kHeaderSize;
            for (const Entry& e : entries) {
                if (!e.removed && !e.synthetic &&
                    (e.kind == Kind::StringIds || e.kind == Kind::TypeIds ||
                     e.kind == Kind::ProtoIds || e.kind == Kind::FieldIds ||
                     e.kind == Kind::MethodIds || e.kind == Kind::ClassDefs ||
                     e.kind == Kind::CallSites || e.kind == Kind::MethodHandles)) {
                    tableEnd = std::max(tableEnd, e.newOff + e.oldLen);
                }
            }
            dataOff = alignUp(tableEnd, 4);
        }
        if (dataOff > total) {
            return Err(WriteError::InvalidModel);
        }
        putU32(out, 104, total - dataOff);
        putU32(out, 108, dataOff);

        const std::array<ca::u8, 20> signature =
            sha1Digest(ByteSlice{out.data() + 32, out.size() - 32});
        std::memcpy(out.data() + 12, signature.data(), signature.size());
        putU32(out, 8, adler32(ByteSlice{out.data() + 12, out.size() - 12}));
    }
    return Ok(std::move(out));
}

}   // namespace dex::core
