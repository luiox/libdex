/// @file        dex_file.hpp
/// @brief       单 DexFile DOM：libdex core 的模型本体。
///
/// 一个 @ref DexFile 就是一个 .dex 文件的完整、可独立析构的所有者：头、
/// map_list 目录、五张全局 ID 表、class_defs，以及按需解码的 string_data /
/// class_data / code_item。它不持有 APK、不持有多 dex 集合、不持有全局索引——
/// 那些是容器层与 mbase 的事。
///
/// eager/lazy 划线（design.md §2.2）：
///   - eager：header、map_list、五张 ID 表的定长条目、class_defs；
///   - lazy：string_data_item（MUTF-8 字节视图）、class_data_item、code_item、
///     type_list，以及后续的 debug_info / annotations / encoded_array。
///
/// 模型关系是一条单纯的拥有链，没有 visitor：
///
/// ```text
/// DexFile ─owns─> 源字节 / DexHeader / MapItem[]
///                / stringIds / typeIds / protoIds / fieldIds / methodIds
///                / classDefs ─lazy─> ClassData ─> EncodedMethod ─lazy─> CodeItem
///                / typeLists ─> 视图（指向源字节）
/// ```
#pragma once

#include <array>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "jstr/mutf8_string.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief DEX 文件头（header_item）。版本 041 起多出 container_size/header_offset。
struct DexHeader
{
    ca::u16 version = 0;
    ca::u32 checksum = 0;
    std::array<ca::u8, 20> signature{};

    ca::u32 fileSize = 0;
    ca::u32 headerSize = 0;
    ca::u32 endianTag = 0;

    ca::u32 linkSize = 0;
    ca::u32 linkOff = 0;
    ca::u32 mapOff = 0;

    ca::u32 stringIdsSize = 0;
    ca::u32 stringIdsOff = 0;
    ca::u32 typeIdsSize = 0;
    ca::u32 typeIdsOff = 0;
    ca::u32 protoIdsSize = 0;
    ca::u32 protoIdsOff = 0;
    ca::u32 fieldIdsSize = 0;
    ca::u32 fieldIdsOff = 0;
    ca::u32 methodIdsSize = 0;
    ca::u32 methodIdsOff = 0;
    ca::u32 classDefsSize = 0;
    ca::u32 classDefsOff = 0;

    ca::u32 dataSize = 0;
    ca::u32 dataOff = 0;

    /// @brief v041 container 头扩展；旧版本为 0。
    ca::u32 containerSize = 0;
    ca::u32 headerOffset = 0;
};

/// @brief map_list 的 section 类型。
///
/// 未知类型不拒绝：未来版本新增 section 时按原样保留，只有修改写回阶段
/// 才需要判断是否建模。
enum class MapType : ca::u16 {
    HeaderItem = 0x0000,
    StringIdItem = 0x0001,
    TypeIdItem = 0x0002,
    ProtoIdItem = 0x0003,
    FieldIdItem = 0x0004,
    MethodIdItem = 0x0005,
    ClassDefItem = 0x0006,
    CallSiteIdItem = 0x0007,
    MethodHandleItem = 0x0008,
    MapList = 0x1000,
    TypeList = 0x1001,
    AnnotationSetRefList = 0x1002,
    AnnotationSetItem = 0x1003,
    ClassDataItem = 0x2000,
    CodeItem = 0x2001,
    StringDataItem = 0x2002,
    DebugInfoItem = 0x2003,
    AnnotationItem = 0x2004,
    EncodedArrayItem = 0x2005,
    AnnotationsDirectoryItem = 0x2006,
};

/// @brief map_list 的单条记录。
struct MapItem
{
    MapType type = MapType::HeaderItem;
    ca::u16 unused = 0;
    ca::u32 size = 0;
    ca::u32 offset = 0;
};

/// @brief string_id_item：指向 string_data_item 的文件偏移。
struct StringId
{
    ca::u32 dataOff = 0;
};

/// @brief type_id_item：指向类型描述符字符串的 string 索引。
struct TypeId
{
    ca::u32 descriptorIdx = 0;
};

/// @brief proto_id_item：shorty + 返回类型 + 参数 type_list 偏移。
struct ProtoId
{
    ca::u32 shortyIdx = 0;
    ca::u32 returnTypeIdx = 0;
    ca::u32 parametersOff = 0;
};

/// @brief field_id_item：声明类 + 类型 + 名字。
struct FieldId
{
    ca::u16 classIdx = 0;
    ca::u16 typeIdx = 0;
    ca::u32 nameIdx = 0;
};

/// @brief method_id_item：声明类 + 原型 + 名字。
struct MethodId
{
    ca::u16 classIdx = 0;
    ca::u16 protoIdx = 0;
    ca::u32 nameIdx = 0;
};

/// @brief class_def_item：类身份绑定 class_idx（type 索引）。
struct ClassDef
{
    ca::u32 classIdx = 0;
    ca::u32 accessFlags = 0;
    ca::u32 superclassIdx = 0;   ///< kNoIndex 表示无父类
    ca::u32 interfacesOff = 0;   ///< 0 表示无接口
    ca::u32 sourceFileIdx = 0;   ///< kNoIndex 表示无来源文件
    ca::u32 annotationsOff = 0;  ///< 0 表示无注解目录
    ca::u32 classDataOff = 0;    ///< 0 表示无类数据（标记接口）
    ca::u32 staticValuesOff = 0; ///< 0 表示无静态初值
};

/// @brief class_data_item 的字段条目（索引已从差分展开为绝对值）。
struct EncodedField
{
    ca::u32 fieldIndex = 0;
    ca::u32 accessFlags = 0;
};

/// @brief class_data_item 的方法条目（code_off 保留为文件偏移）。
struct EncodedMethod
{
    ca::u32 methodIndex = 0;
    ca::u32 accessFlags = 0;
    ca::u32 codeOff = 0;  ///< 0 表示抽象/本地方法，无 code_item
};

/// @brief 单类的 class_data_item：字段与方法目录。
///
/// 解码只到目录层：方法体、debug_info、注解内容都保持 lazy。
struct ClassData
{
    ByteSpan raw;  ///< 源字节中的完整编码区间
    std::vector<EncodedField> staticFields;
    std::vector<EncodedField> instanceFields;
    std::vector<EncodedMethod> directMethods;
    std::vector<EncodedMethod> virtualMethods;
};

/// @brief encoded_catch_handler 中的一条 typed catch。
struct TypedCatch
{
    ca::u32 typeIdx = 0;
    ca::u32 address = 0;
};

/// @brief encoded_catch_handler：typed 列表 + 可选 catch-all。
struct CatchHandler
{
    std::vector<TypedCatch> typed;
    bool hasCatchAll = false;
    ca::u32 catchAllAddress = 0;
};

/// @brief try_item 与其解析后的 handler 下标。
struct TryBlock
{
    ca::u32 startAddress = 0;
    ca::u16 insnCount = 0;
    ca::u16 handlerOff = 0;   ///< 相对 encoded_catch_handler_list 起始
    ca::u32 handlerIndex = 0; ///< 指向 CodeItem::catchHandlers
};

/// @brief code_item 的目录级模型：头部 + 指令区 span + tries/handlers。
///
/// 指令流由 @ref decodeInsns 解码；编码处理器表在此解析为结构化条目，供
/// try 区域与后续 IR 使用。
struct CodeItem
{
    ByteSpan raw;      ///< 从 code_item 起始到 tries 末尾（不含编码处理器表）
    ByteSpan insns;    ///< insns_size 个 u16 指令单元
    ByteSpan tries;    ///< tries_size 条 try_item（每条 8 字节）
    ByteSpan handlers; ///< encoded_catch_handler_list（含 handler 计数）
    ca::u32 offset = 0;
    ca::u32 debugInfoOff = 0;
    ca::u32 handlersOff = 0;  ///< 0 表示无 tries
    ca::u16 registersSize = 0;
    ca::u16 insSize = 0;
    ca::u16 outsSize = 0;
    ca::u16 triesSize = 0;
    ca::u32 insnsSize = 0;
    std::vector<TryBlock> tryBlocks;
    std::vector<CatchHandler> catchHandlers;
};

/// @brief 解析一个 code_item，不依赖 DexFile。
///
/// @param source 整个 dex 的源字节；offset 是 code_item 起始。
/// @param typeCount 仅用于对 catch 的 type 索引做 BadIndex 诊断；0 表示跳过。
/// @param diagnostics 非空时收集语义告警（try 范围/handler 地址越界、悬垂类型索引）；
///        结构性错误仍返回 Err(ReadError::BadCodeItem)。
Result<CodeItem, ReadError> parseCodeItem(ByteSlice source, ca::u32 offset,
                                          ca::u32 typeCount = 0,
                                          Diagnostics* diagnostics = nullptr);

/// @brief type_list_item 的零拷贝视图（条目为小端 u16 类型索引）。
struct TypeListSpan
{
    ByteSpan raw;                     ///< 含 size 字段的完整区间
    ca::u32 size = 0;
    const ca::u8* entries = nullptr;  ///< size*2 字节

    bool empty() const noexcept { return size == 0; }

    /// @brief 取第 i 个类型索引；调用方保证 i < size（越界是调用方错误）。
    ca::u16 at(ca::u32 i) const noexcept
    {
        const ca::u8* p = entries + static_cast<ca::usize>(i) * 2;
        return static_cast<ca::u16>(static_cast<ca::u16>(p[0]) |
                                    static_cast<ca::u16>(static_cast<ca::u16>(p[1]) << 8));
    }
};

/// @brief 单 DexFile DOM 的唯一所有者。
///
/// 生命周期只有一条规则：本对象析构，其下一切（源字节副本、ID 表、懒解码
/// 产物）一次回收。公共 API 不产生调用方必须 delete 的裸指针。
class DexFile
{
public:
    /// @brief DEX 的「无索引」哨兵（superclass_idx / source_file_idx）。
    static constexpr ca::u32 kNoIndex = 0xFFFFFFFFu;

    DexFile() = default;
    DexFile(const DexFile&) = delete;
    DexFile& operator=(const DexFile&) = delete;

    // ---- 骨架（eager）----

    DexHeader header;
    std::vector<MapItem> mapItems;
    std::vector<StringId> stringIds;
    std::vector<TypeId> typeIds;
    std::vector<ProtoId> protoIds;
    std::vector<FieldId> fieldIds;
    std::vector<MethodId> methodIds;
    std::vector<ClassDef> classDefs;

    // ---- 源字节：lazy 与 copy-through 保真的共同前提 ----

    bool hasSource() const noexcept { return !sourceBytes_.is_empty(); }

    /// @brief 整份源字节的零拷贝视图。
    ByteSlice source() const noexcept
    {
        return sourceBytes_.is_empty()
                   ? ByteSlice{}
                   : ByteSlice{sourceBytes_.as_ptr(), sourceBytes_.len()};
    }

    /// @brief libca Bytes 形态的源字节（共享存储），供需要随机访问的消费者
    ///        用 @ref Reader::at 切片。
    const ca::core::Bytes& sourceBytes() const noexcept { return sourceBytes_; }

    /// @brief 复制入参字节进模型（libca Bytes 自有存储）。重复调用会使既有
    ///        span/视图失效，仅由 reader 调用。
    void adoptSource(ByteSlice bytes);

    /// @brief 接管一份已有的 libca Bytes（共享存储，不复制内容）。
    void adoptSource(ca::core::Bytes bytes) noexcept { sourceBytes_ = std::move(bytes); }

    /// @brief 借用调用方字节（不复制）。调用方必须保证字节在模型存活期内有效。
    void adoptBorrowedSource(ByteSlice bytes) noexcept;

    // ---- 解析状态与诊断 ----

    ParseState state() const noexcept { return state_; }
    void setState(ParseState s) noexcept { state_ = s; }
    const Diagnostics& diagnostics() const noexcept { return diag_; }
    Diagnostics& diagnostics() noexcept { return diag_; }

    // ---- 表计数（= 头部声明值，解析后与 vector 长度一致）----

    ca::u32 stringCount() const noexcept { return static_cast<ca::u32>(stringIds.size()); }
    ca::u32 typeCount() const noexcept { return static_cast<ca::u32>(typeIds.size()); }
    ca::u32 protoCount() const noexcept { return static_cast<ca::u32>(protoIds.size()); }
    ca::u32 fieldCount() const noexcept { return static_cast<ca::u32>(fieldIds.size()); }
    ca::u32 methodCount() const noexcept { return static_cast<ca::u32>(methodIds.size()); }
    ca::u32 classCount() const noexcept { return static_cast<ca::u32>(classDefs.size()); }

    /// @brief 按 section 类型查 map_item；不存在返回 nullptr。
    const MapItem* findMapItem(MapType type) const noexcept;

    // ---- lazy 解码：字符串 ----

    /// @brief 第 index 个 string_data_item 的 MUTF-8 字节视图（零拷贝）。
    ///
    /// 首次调用解码并缓存；失败结果同样缓存，重复调用返回同一个错误。
    Result<jstr::MUtf8StringRef, ReadError> string(ca::u32 index);

    /// @brief 已解码的字符串视图；未解码或索引非法返回 nullptr（peek 不置脏、不解码）。
    const jstr::MUtf8StringRef* peekString(ca::u32 index) const noexcept;

    // ---- lazy 解码：类型与列表 ----

    /// @brief 类型描述符（type_id → string_id → string_data）。
    Result<jstr::MUtf8StringRef, ReadError> typeDescriptor(ca::u32 typeIdx);

    /// @brief 类描述符（class_def → class_idx → type 描述符）。
    Result<jstr::MUtf8StringRef, ReadError> classDescriptor(ca::u32 classDefIdx);

    /// @brief 父类描述符；superclass_idx 为 kNoIndex 时返回空视图（Ok）。
    Result<jstr::MUtf8StringRef, ReadError> superclassDescriptor(ca::u32 classDefIdx);

    /// @brief 来源文件名；source_file_idx 为 kNoIndex 时返回空视图（Ok）。
    Result<jstr::MUtf8StringRef, ReadError> sourceFile(ca::u32 classDefIdx);

    /// @brief 解析任意 type_list 偏移；offset 为 0 时返回空列表。
    Result<TypeListSpan, ReadError> typeList(ca::u32 offset);

    /// @brief 方法原型的参数类型列表；parameters_off 为 0 时返回空列表。
    Result<TypeListSpan, ReadError> protoParameters(ca::u32 protoIdx);

    /// @brief 类实现的接口列表；interfaces_off 为 0 时返回空列表。
    Result<TypeListSpan, ReadError> interfaces(ca::u32 classDefIdx);

    // ---- lazy 解码：成员名/描述符 ----

    Result<jstr::MUtf8StringRef, ReadError> fieldClassDescriptor(ca::u32 fieldIdx);
    Result<jstr::MUtf8StringRef, ReadError> fieldTypeDescriptor(ca::u32 fieldIdx);
    Result<jstr::MUtf8StringRef, ReadError> fieldName(ca::u32 fieldIdx);

    Result<jstr::MUtf8StringRef, ReadError> methodClassDescriptor(ca::u32 methodIdx);
    Result<jstr::MUtf8StringRef, ReadError> methodName(ca::u32 methodIdx);

    // ---- lazy 解码：类数据与方法体 ----

    /// @brief 解码 class_data_item；class_data_off 为 0 时返回 Ok(nullptr)。
    Result<const ClassData*, ReadError> classData(ca::u32 classDefIdx);

    /// @brief 已解码的 class_data；未解码或索引非法返回 nullptr。
    const ClassData* peekClassData(ca::u32 classDefIdx) const noexcept;

    /// @brief 解码 code_item；codeOff 为 0 时返回 Ok(nullptr)。
    Result<const CodeItem*, ReadError> codeItem(ca::u32 codeOff);

    /// @brief 已解码的 code_item；未解码返回 nullptr。
    const CodeItem* peekCodeItem(ca::u32 codeOff) const noexcept;

private:
    struct LazyString
    {
        enum class State : ca::u8 { Untouched, Decoded, Failed };

        State state = State::Untouched;
        ReadError error = ReadError::Ok;
        jstr::MUtf8StringRef view;
    };

    struct LazyClassData
    {
        enum class State : ca::u8 { Untouched, Decoded, Failed };

        State state = State::Untouched;
        ReadError error = ReadError::Ok;
        std::unique_ptr<ClassData> data;  ///< Decoded 且类无 class_data 时为 nullptr
    };

    Result<std::unique_ptr<ClassData>, ReadError> decodeClassData(ca::u32 offset);
    Result<std::unique_ptr<CodeItem>, ReadError> decodeCodeItem(ca::u32 offset);

    ca::core::Bytes sourceBytes_;  ///< 源字节存储（自有 copy 或静态借用）
    ParseState state_ = ParseState::Validated;
    Diagnostics diag_;

    std::vector<LazyString> stringCache_;
    std::vector<LazyClassData> classDataCache_;
    std::unordered_map<ca::u32, std::unique_ptr<CodeItem>> codeCache_;
    std::unordered_map<ca::u32, ReadError> codeFailures_;
};

}   // namespace dex::core
