/// @file        dex_file.hpp
/// @brief       单 DexFile DOM：libdex core 的模型本体。
///
/// 一个 @ref DexFile 就是一个 .dex 文件的完整、可独立析构的所有者：头、
/// map_list 目录、五张全局 ID 表、class_defs，以及按需解码的 string_data /
/// class_data / code_item。@ref internString 追加的字符串由同一个对象持有，
/// 与源字符串共用懒解码入口。它不持有 APK、不持有多 dex 集合、不持有全局
/// 索引——那些是容器层与 mbase 的事。
///
/// eager/lazy 划线：
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
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "jstr/mutf8_string.hpp"

#include "dex/core/annotation.hpp"
#include "dex/core/bytes.hpp"
#include "dex/core/debug_info.hpp"
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

/// @brief 未建模 map section 的原始区间。
///
/// 区间从 section 起始到下一个 map 条目（或文件尾）；长度含对齐填充，
/// 因为未知 section 的条目边界不可知。写回时按原字节透传。
struct RawSection
{
    ca::u16 type = 0;  ///< 原始 map type 值（含未知类型）
    ca::u32 size = 0;  ///< map 声明的条目数
    ByteSpan span;
};

/// @brief 该 map 类型是否已有结构化条目模型。
bool isModeledMapType(MapType type) noexcept;

/// @brief string_id_item：指向 string_data_item 的文件偏移。
///
/// @ref owned 为 true 的条目指向 @ref DexFile 的自有字符串池（由
/// @ref DexFile::internString 追加），不占用源文件偏移；@ref ownedIndex 是池
/// 下标。两种形态都是完整的 string_data_item 编码（ULEB 长度 + MUTF-8 + NUL）。
struct StringId
{
    ca::u32 dataOff = 0;     ///< 源文件偏移；owned 为 true 时忽略
    ca::u32 ownedIndex = 0;  ///< 自有字符串池下标；owned 为 false 时忽略
    bool owned = false;      ///< 字符串是否来自自有池而非源字节
};

/// @brief type_id_item：指向类型描述符字符串的 string 索引。
struct TypeId
{
    ca::u32 descriptorIdx = 0;
};

/// @brief proto_id_item：shorty + 返回类型 + 参数 type_list 偏移。
///
/// @ref ownedParameters 为 true 时参数取 @ref DexFile 自有 type_list 池的
/// @ref ownedParametersIdx 条目，@ref parametersOff 被忽略；@ref buildDex 会把
/// 自有列表发射为新 type_list 并回填真实偏移。
struct ProtoId
{
    ca::u32 shortyIdx = 0;
    ca::u32 returnTypeIdx = 0;
    ca::u32 parametersOff = 0;
    ca::u32 ownedParametersIdx = 0;  ///< 自有 type_list 池下标；ownedParameters 为 false 时忽略
    bool ownedParameters = false;    ///< 参数是否来自自有池而非源文件偏移
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
///
/// @ref ownedInterfaces 为 true 时接口列表取 @ref DexFile 自有 type_list 池的
/// @ref ownedInterfacesIdx 条目，@ref interfacesOff 被忽略；@ref buildDex 会把
/// 自有列表发射为新 type_list 并回填真实偏移。
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
    ca::u32 ownedInterfacesIdx = 0;  ///< 自有 type_list 池下标；ownedInterfaces 为 false 时忽略
    bool ownedInterfaces = false;    ///< 接口列表是否来自自有池而非源文件偏移
};

/// @brief call_site_id_item：指向一个 encoded_array_item。
struct CallSiteId
{
    ca::u32 callSiteOff = 0;
};

/// @brief method_handle_item：类型、目标索引与两个未用字段。
///
/// @ref handleType 决定 @ref targetIdx 指向 field_ids 还是 method_ids；
/// 两个 unused 字段原样保留，不按规范值清零。
struct MethodHandle
{
    ca::u16 handleType = 0;
    ca::u16 unused1 = 0;
    ca::u16 targetIdx = 0;
    ca::u16 unused2 = 0;
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

/// @brief 精确重编码 class_data_item；字段/方法的索引差分由本函数计算。
///
/// 各组索引必须严格递增；否则返回 Err(WriteError::Unencodable)。写回顺序
/// 与模型中的四处列表一致（static/instance fields、direct/virtual methods）。
Result<std::vector<ca::u8>, WriteError> writeClassData(const ClassData& data);

/// @brief 精确重编码 code_item。
///
/// @param item 头部、tries 与 handler 模型；tries 的 handler_off 按
///             @ref TryBlock::handlerIndex 重新计算，共享的 handler 保持共享。
/// @param insns 已编码的指令区字节，长度必须是 `insnsSize * 2`。
/// 若 tries 非空且指令数为奇数，写回按格式补 2 字节对齐。
Result<std::vector<ca::u8>, WriteError> writeCodeItem(const CodeItem& item, ByteSlice insns);

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

/// @brief 一个类的注解覆盖：哪些注解集由自有注解项池重建。
///
/// 只记录显式覆盖：字段/方法/参数的 map 中「存在键」即覆盖该成员（空向量
/// 表示清空该成员的注解条目），未出现的成员沿用源 annotations_directory。
/// std::map 按 memberIdx 排序，保证重建发射顺序确定。
struct AnnotationAttachments
{
    bool hasClass = false;                        ///< 是否覆盖类注解集
    std::vector<ca::u32> classItems;              ///< 类注解集：注解项池下标，空=清空
    std::map<ca::u32, std::vector<ca::u32>> fields;    ///< fieldIdx → 池下标
    std::map<ca::u32, std::vector<ca::u32>> methods;   ///< methodIdx → 池下标
    /// methodIdx → 每参数一组的池下标；内层空向量表示该参数无注解。
    std::map<ca::u32, std::vector<std::vector<ca::u32>>> parameters;

    bool empty() const noexcept
    {
        return !hasClass && fields.empty() && methods.empty() && parameters.empty();
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

    /// @brief type/proto/field/method 表的最大条目数（16 位索引）。
    static constexpr ca::u32 kIdTableLimit = 0x10000u;

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
    std::vector<CallSiteId> callSites;        ///< map_list 中有该 section 时填充
    std::vector<MethodHandle> methodHandles;  ///< map_list 中有该 section 时填充

    /// @brief 未建模的 map section（如 hiddenapi）；按 map 偏移升序。
    std::vector<RawSection> rawSections;

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
    ca::u32 callSiteCount() const noexcept { return static_cast<ca::u32>(callSites.size()); }
    ca::u32 methodHandleCount() const noexcept
    {
        return static_cast<ca::u32>(methodHandles.size());
    }

    /// @brief 按 section 类型查 map_item；不存在返回 nullptr。
    const MapItem* findMapItem(MapType type) const noexcept;

    // ---- lazy 解码：字符串 ----

    /// @brief 第 index 个 string_data_item 的 MUTF-8 字节视图（零拷贝）。
    ///
    /// 首次调用解码并缓存；失败结果同样缓存，重复调用返回同一个错误。
    Result<jstr::MUtf8StringRef, ReadError> string(ca::u32 index);

    /// @brief 已解码的字符串视图；未解码或索引非法返回 nullptr（peek 不置脏、不解码）。
    const jstr::MUtf8StringRef* peekString(ca::u32 index) const noexcept;

    /// @brief 第 index 个条目的完整 string_data_item 字节（ULEB 长度 + MUTF-8 + NUL）。
    ///
    /// 源字符串与自有字符串统一走本入口；builder 用它保留非最小 ULEB 编码。
    Result<std::vector<ca::u8>, ReadError> stringData(ca::u32 index) const;

    /// @brief 追加一个 MUTF-8 字符串并返回 string 索引；内容已存在时复用旧索引。
    ///
    /// 输入必须是合法 MUTF-8（无裸 NUL、无四字节序列）；错误返回
    /// @ref ReadError::BadStringData。新条目由本对象持有，不写回源字节；
    /// @ref buildDex 会把它并入 canonical 字符串池并重排所有字符串索引。
    /// 调用方修改 `stringIds` 后需保证自上次 intern 以来条目未变，否则查重表
    /// 可能过期（追加条目会自动重建，原地改写不会）。
    Result<ca::u32, ReadError> internString(jstr::MUtf8StringRef mutf8);

    /// @brief 把标准 UTF-8 转成 MUTF-8 后追加；语义同 @ref internString。
    Result<ca::u32, ReadError> internUtf8(std::string_view utf8);

    // ---- ID 表条目追加 ----
    //
    // 只追加或复用条目，不保证表内顺序；@ref buildDex 重建时会按 DEX 排序键
    // 重排并重写全部索引。成员索引（class/proto/name/type）必须已存在；
    // 表达到 @ref kIdTableLimit 时返回 @ref ReadError::IdTableFull。

    /// @brief 追加或复用 type_ids 条目，返回 type 索引。
    ///
    /// @p descriptor 按标准 UTF-8 转入 MUTF-8；内容相同的字符串与 type 复用。
    Result<ca::u32, ReadError> addType(std::string_view descriptor);

    /// @brief 追加或复用 proto_ids 条目。
    ///
    /// @p parametersOff 为 0（无参数）或指向本文件内可解析的 type_list；
    /// 参数列表按内容比较，相同参数列表的不同偏移视为同一条目。
    Result<ca::u32, ReadError> addProto(ca::u32 shortyIdx, ca::u32 returnTypeIdx,
                                        ca::u32 parametersOff);

    /// @brief 追加或复用 field_ids 条目；参数顺序与 @ref FieldId 一致。
    Result<ca::u32, ReadError> addField(ca::u32 classIdx, ca::u32 typeIdx,
                                        ca::u32 nameIdx);

    /// @brief 追加或复用 method_ids 条目；参数顺序与 @ref MethodId 一致。
    Result<ca::u32, ReadError> addMethod(ca::u32 classIdx, ca::u32 protoIdx,
                                         ca::u32 nameIdx);

    // ---- 自有 type_list ----
    //
    // @ref addProto 与类接口原本只能引用源文件已有的 type_list 偏移；自有池
    // 允许新建参数列表与接口列表，@ref buildDex 发射为新的 type_list 条目并
    // 回填真实偏移。池内按内容去重；与源列表内容相同时仍会各自发射（规范
    // 允许重复条目，二次重建保持固定点）。

    /// @brief 追加自有 type_list 并返回池下标；内容重复时复用已有下标。
    ///
    /// @p typeIdxs 每项必须是当前 type_ids 的合法索引，越界返回
    /// @ref ReadError::BadIndex。空列表不占池位，返回 @ref kNoIndex。
    Result<ca::u32, ReadError> addTypeList(const std::vector<ca::u32>& typeIdxs);

    /// @brief 按返回类型与参数列表追加或复用 proto，shorty 自动推导并 intern。
    ///
    /// 与既有 proto 按（返回类型，参数内容）比较，相同则复用。参数类型不能
    /// 是 void；shorty 里对象与数组都记 'L'。
    Result<ca::u32, ReadError> addProtoWithParams(ca::u32 returnTypeIdx,
                                                  const std::vector<ca::u32>& parameters);

    /// @brief 覆盖 class_def 的接口列表；重建时生成新 type_list。
    ///
    /// 覆盖后 @ref ClassDef::interfacesOff 被忽略；空列表等价于无接口。
    Result<void, ReadError> setClassInterfaces(ca::u32 classDefIdx,
                                               const std::vector<ca::u32>& interfaces);

    // ---- 自有注解 ----
    //
    // 注解项先入池，再按类挂到目标成员；@ref buildDex 把覆盖与源
    // annotations_directory 合并成生效目录后重新发射注解族。只覆盖显式
    // 指定的成员，其余沿用源条目；覆盖目标必须在生效 class_data 中有定义
    // （含注入成员），否则重建返回 `InvalidModel`。与 stripAnnotations 同时
    // 使用同样返回 `InvalidModel`。

    /// @brief 追加注解项（可见性 + encoded_annotation），返回池下标。
    ///
    /// 内容（含 valueArg 宽度）相同的项复用旧下标。typeIdx、元素名与值里的
    /// String/Type/Field/Method/Enum/MethodType/MethodHandle 索引必须在当前
    /// 表内，越界返回 @ref ReadError::BadIndex；索引型载荷的 valueArg 过窄
    /// 时按最小宽度改宽。
    Result<ca::u32, ReadError> addAnnotationItem(const AnnotationItem& item);

    /// @brief 覆盖类注解集；空 @p items 清空类注解（annotations_off 目录仍会
    /// 保留其余条目）。
    Result<void, ReadError> setClassAnnotations(ca::u32 classDefIdx,
                                                const std::vector<ca::u32>& items);

    /// @brief 覆盖字段注解集；空 @p items 移除该字段的注解条目。
    Result<void, ReadError> setFieldAnnotations(ca::u32 classDefIdx, ca::u32 fieldIdx,
                                                const std::vector<ca::u32>& items);

    /// @brief 覆盖方法注解集；空 @p items 移除该方法的注解条目。
    Result<void, ReadError> setMethodAnnotations(ca::u32 classDefIdx, ca::u32 methodIdx,
                                                 const std::vector<ca::u32>& items);

    /// @brief 覆盖方法参数注解；第 i 项对应方法 proto 的第 i 个参数。
    ///
    /// 内层空向量表示该参数无注解（ref_list 槽位写 0）。重建时要求长度等于
    /// proto 参数个数。
    Result<void, ReadError> setParameterAnnotations(
        ca::u32 classDefIdx, ca::u32 methodIdx,
        const std::vector<std::vector<ca::u32>>& perParameter);

    /// @brief 自有注解项池的只读访问；下标越界返回 nullptr。
    const AnnotationItem* ownedAnnotationItem(ca::u32 index) const noexcept;

    /// @brief 自有注解项池的条目数（越界判断用）。
    ca::u32 ownedAnnotationItemCount() const noexcept
    {
        return static_cast<ca::u32>(ownedAnnotationItems_.size());
    }

    /// @brief 逐类注解覆盖表（classDefIdx → 附件），供 builder 与查询用。
    const std::map<ca::u32, AnnotationAttachments>& annotationAttachments() const noexcept
    {
        return ownedAnnotations_;
    }

    /// @brief 自有 type_list 的零拷贝视图；下标越界返回 size=0、entries=nullptr。
    ///
    /// 视图指向模型自有字节，在模型存活且不再 addTypeList 期间有效；
    /// @ref protoParameters 与 @ref interfaces 的 owned 分支也走这里。
    TypeListSpan ownedTypeListSpan(ca::u32 index) const noexcept;

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

    // ---- lazy 解码：注解与静态初值 ----
    //
    // 每个条目的入口都是文件偏移：class_def / annotations_directory /
    // annotation_set 里的偏移原样保留，调用方可以从任意一层进入，共享的
    // set/item 按偏移去重。off 为 0 时返回 Ok(nullptr)。

    /// @brief annotations_directory_item（class_def.annotations_off 的落点）。
    Result<const AnnotationsDirectory*, ReadError> annotationsDirectory(ca::u32 offset);

    /// @brief annotation_set_item。
    Result<const AnnotationSetItem*, ReadError> annotationSet(ca::u32 offset);

    /// @brief annotation_set_ref_list（参数注解）。
    Result<const AnnotationSetRefList*, ReadError> annotationSetRefList(ca::u32 offset);

    /// @brief annotation_item（annotation_set 条目的落点）。
    Result<const AnnotationItem*, ReadError> annotationItem(ca::u32 offset);

    /// @brief encoded_array_item（class_def.static_values_off 的落点）。
    Result<const EncodedArrayItem*, ReadError> encodedArray(ca::u32 offset);

    /// @brief 类的注解目录；无注解返回 Ok(nullptr)。
    Result<const AnnotationsDirectory*, ReadError> classAnnotations(ca::u32 classDefIdx);

    /// @brief 类的静态字段初值；无初值返回 Ok(nullptr)。
    Result<const EncodedArrayItem*, ReadError> staticValues(ca::u32 classDefIdx);

    /// @brief debug_info_item；offset 为 0 时返回 Ok(nullptr)。
    Result<const DebugInfo*, ReadError> debugInfo(ca::u32 offset);

    /// @brief 第 index 个 call_site 的 encoded_array_item；越界返回 BadIndex。
    Result<const EncodedArrayItem*, ReadError> callSiteValues(ca::u32 index);

private:
    template <typename T>
    struct LazyItem
    {
        enum class State : ca::u8 { Untouched, Decoded, Failed };

        State state = State::Untouched;
        ReadError error = ReadError::Ok;
        std::unique_ptr<T> item;
    };

    template <typename T>
    Result<const T*, ReadError> decodeLazy(std::unordered_map<ca::u32, LazyItem<T>>& cache,
                                           ca::u32 offset,
                                           Result<T, ReadError> (*decode)(ByteSlice, ca::u32));

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

    void refreshInternIndex();

    ca::core::Bytes sourceBytes_;  ///< 源字节存储（自有 copy 或静态借用）
    /// 自有 string_data_item 块；deque保证追加时既有视图地址不变。
    std::deque<std::vector<ca::u8>> ownedStrings_;
    std::unordered_map<std::string, ca::u32> internIndex_;
    ca::usize internIndexedCount_ = 0;
    /// 自有 type_list 池：已编码的 type_list 字节（u32 计数 + u16 LE 条目），
    /// 由 addTypeList/addProtoWithParams/setClassInterfaces 填充。
    std::deque<std::vector<ca::u8>> ownedTypeLists_;
    /// 自有注解项池（按内容去重）与逐类覆盖表。
    std::deque<AnnotationItem> ownedAnnotationItems_;
    std::map<ca::u32, AnnotationAttachments> ownedAnnotations_;
    ParseState state_ = ParseState::Validated;
    Diagnostics diag_;

    std::vector<LazyString> stringCache_;
    std::vector<LazyClassData> classDataCache_;
    std::unordered_map<ca::u32, std::unique_ptr<CodeItem>> codeCache_;
    std::unordered_map<ca::u32, ReadError> codeFailures_;

    /// @brief 数据区条目的 offset → 解码结果缓存（同一偏移只解一次）。
    std::unordered_map<ca::u32, LazyItem<AnnotationsDirectory>> annotationsDirectoryCache_;
    std::unordered_map<ca::u32, LazyItem<AnnotationSetItem>> annotationSetCache_;
    std::unordered_map<ca::u32, LazyItem<AnnotationSetRefList>> annotationSetRefCache_;
    std::unordered_map<ca::u32, LazyItem<AnnotationItem>> annotationItemCache_;
    std::unordered_map<ca::u32, LazyItem<EncodedArrayItem>> encodedArrayCache_;
    std::unordered_map<ca::u32, LazyItem<DebugInfo>> debugInfoCache_;
};

}   // namespace dex::core
