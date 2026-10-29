/// @file        dex_file.cpp
/// @brief       DexFile 的 lazy 解码与查询实现。
#include "dex/dex_file.hpp"

#include <cstring>
#include <unordered_map>

#include "jstr/conversion.hpp"

#include "dex/leb128.hpp"

namespace dex::core {

namespace {

struct StringBody
{
    const ca::u8* base = nullptr;
    ca::usize begin = 0;
    ca::usize end = 0;  ///< 终止 NUL 的位置（不含）
};

/// @brief 定位 string_data_item 的 MUTF-8 主体，不校验其编码。
Result<StringBody, ReadError> locateStringBody(ByteSlice storage, ca::u32 offset)
{
    if (offset >= storage.size()) {
        return Err(ReadError::BadStringData);
    }
    const ca::core::Bytes bytes = ca::core::Bytes::from_static(storage.data(), storage.size());
    Result<Reader, ReadError> reader = Reader::at(bytes, offset);
    if (reader.is_err()) {
        return Err(ReadError::BadStringData);
    }
    Reader cur = std::move(reader).unwrap();
    const Result<ca::u32, ReadError> length = readUleb128(cur);
    if (length.is_err()) {
        return Err(length.unwrap_err());
    }

    const ca::u8* base = storage.data();
    const ca::usize start = cur.pos();
    if (start >= storage.size()) {
        return Err(ReadError::BadStringData);
    }
    const void* nul = std::memchr(base + start, 0, storage.size() - start);
    if (nul == nullptr) {
        return Err(ReadError::BadStringData);
    }
    return Ok(StringBody{base, start,
                         static_cast<ca::usize>(static_cast<const ca::u8*>(nul) - base)});
}

}   // namespace

std::unique_ptr<DexFile> DexFile::createEmpty(ca::u16 version)
{
    auto dex = std::unique_ptr<DexFile>(new DexFile());
    dex->header.version = version;
    dex->header.endianTag = 0x12345678u;
    return dex;
}

void DexFile::adoptSource(ByteSlice bytes)
{
    if (bytes.empty()) {
        pools_.sourceBytes = ca::core::Bytes{};
        return;
    }
    pools_.sourceBytes = ca::core::Bytes::copy_from_slice(bytes.data(), bytes.size());
}

void DexFile::adoptBorrowedSource(ByteSlice bytes) noexcept
{
    pools_.sourceBytes = ca::core::Bytes::from_static(bytes.data(), bytes.size());
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

bool isModeledMapType(MapType type) noexcept
{
    switch (type) {
        case MapType::HeaderItem:
        case MapType::StringIdItem:
        case MapType::TypeIdItem:
        case MapType::ProtoIdItem:
        case MapType::FieldIdItem:
        case MapType::MethodIdItem:
        case MapType::ClassDefItem:
        case MapType::CallSiteIdItem:
        case MapType::MethodHandleItem:
        case MapType::MapList:
        case MapType::TypeList:
        case MapType::AnnotationSetRefList:
        case MapType::AnnotationSetItem:
        case MapType::ClassDataItem:
        case MapType::CodeItem:
        case MapType::StringDataItem:
        case MapType::DebugInfoItem:
        case MapType::AnnotationItem:
        case MapType::EncodedArrayItem:
        case MapType::AnnotationsDirectoryItem:
            return true;
    }
    return false;
}

Result<jstr::MUtf8StringRef, ReadError> DexFile::string(ca::u32 index)
{
    if (index >= stringIds.size()) {
        return Err(ReadError::BadIndex);
    }

    if (caches_.strings.size() != stringIds.size()) {
        caches_.strings.resize(stringIds.size());
    }
    LazyString& slot = caches_.strings[index];
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

    const StringId& id = stringIds[index];
    ByteSlice storage;
    ca::u32 offset = 0;
    if (id.owned) {
        if (id.ownedIndex >= pools_.strings.size()) {
            return fail(ReadError::BadStringData);
        }
        const std::vector<ca::u8>& bytes = pools_.strings[id.ownedIndex];
        storage = ByteSlice{bytes.data(), bytes.size()};
    } else {
        storage = source();
        offset = id.dataOff;
    }

    Result<StringBody, ReadError> body = locateStringBody(storage, offset);
    if (body.is_err()) {
        return fail(body.unwrap_err());
    }
    const StringBody& located = body.unwrap();

    slot.view = jstr::MUtf8StringRef(
        reinterpret_cast<const char*>(located.base + located.begin),
        located.end - located.begin);
    slot.state = LazyString::State::Decoded;
    return Ok(slot.view);
}

Result<std::vector<ca::u8>, ReadError> DexFile::stringData(ca::u32 index) const
{
    if (index >= stringIds.size()) {
        return Err(ReadError::BadIndex);
    }
    const StringId& id = stringIds[index];
    if (id.owned) {
        if (id.ownedIndex >= pools_.strings.size()) {
            return Err(ReadError::BadStringData);
        }
        const std::vector<ca::u8>& bytes = pools_.strings[id.ownedIndex];
        return Ok(std::vector<ca::u8>(bytes.begin(), bytes.end()));
    }

    const ByteSlice storage = source();
    Result<StringBody, ReadError> body = locateStringBody(storage, id.dataOff);
    if (body.is_err()) {
        return Err(body.unwrap_err());
    }
    const StringBody& located = body.unwrap();
    return Ok(std::vector<ca::u8>(located.base + id.dataOff,
                                  located.base + located.end + 1));
}

Result<ca::u32, ReadError> DexFile::internString(jstr::MUtf8StringRef mutf8)
{
    Result<std::u16string, jstr::EncodingError> decoded = jstr::mutf8_to_utf16(mutf8);
    if (decoded.is_err()) {
        return Err(ReadError::BadStringData);
    }
    const std::u16string units = std::move(decoded).unwrap();
    if (units.size() > 0xFFFFFFFFu) {
        return Err(ReadError::BadStringData);
    }

    if (pools_.stringInternedCount != stringIds.size()) {
        refreshInternIndex();
    }

    std::string key;
    if (!mutf8.empty()) {
        key.assign(mutf8.data(), mutf8.size());
    }
    const auto found = pools_.stringIntern.find(key);
    if (found != pools_.stringIntern.end()) {
        return Ok(found->second);
    }

    std::vector<ca::u8> item;
    writeUleb128(item, static_cast<ca::u32>(units.size()));
    item.insert(item.end(), mutf8.begin(), mutf8.end());
    item.push_back(0);
    pools_.strings.push_back(std::move(item));

    StringId id;
    id.owned = true;
    id.ownedIndex = static_cast<ca::u32>(pools_.strings.size() - 1);
    stringIds.push_back(id);

    const ca::u32 index = static_cast<ca::u32>(stringIds.size() - 1);
    pools_.stringIntern.emplace(std::move(key), index);
    pools_.stringInternedCount = stringIds.size();
    return Ok(index);
}

Result<ca::u32, ReadError> DexFile::internUtf8(std::string_view utf8)
{
    const std::string text(utf8);
    Result<jstr::MUtf8String, jstr::EncodingError> converted = jstr::utf8_to_mutf8(text);
    if (converted.is_err()) {
        return Err(ReadError::BadStringData);
    }
    const jstr::MUtf8String mutf8 = std::move(converted).unwrap();
    return internString(mutf8.view());
}

Result<ca::u32, ReadError> DexFile::addType(std::string_view descriptor)
{
    Result<ca::u32, ReadError> interned = internUtf8(descriptor);
    if (interned.is_err()) {
        return Err(interned.unwrap_err());
    }
    const ca::u32 descriptorIdx = interned.unwrap();
    ensureIdIndexes();
    const auto found = pools_.typeIndexByKey.find(descriptorIdx);
    if (found != pools_.typeIndexByKey.end()) {
        return Ok(found->second);
    }
    if (typeIds.size() >= kIdTableLimit) {
        return Err(ReadError::IdTableFull);
    }
    const ca::u32 index = static_cast<ca::u32>(typeIds.size());
    typeIds.push_back(TypeId{descriptorIdx});
    pools_.typeIndexByKey.emplace(descriptorIdx, index);
    pools_.typeIndexedCount = typeIds.size();
    return Ok(index);
}

Result<ca::u32, ReadError> DexFile::addProto(ca::u32 shortyIdx, ca::u32 returnTypeIdx,
                                             ca::u32 parametersOff)
{
    if (shortyIdx >= stringIds.size() || returnTypeIdx >= typeIds.size()) {
        return Err(ReadError::BadIndex);
    }
    Result<TypeListSpan, ReadError> fetched = typeList(parametersOff);
    if (fetched.is_err()) {
        return Err(fetched.unwrap_err());
    }
    const TypeListSpan params = fetched.unwrap();
    for (ca::u32 i = 0; i < params.size; ++i) {
        if (params.at(i) >= typeIds.size()) {
            return Err(ReadError::BadIndex);
        }
    }

    ensureIdIndexes();
    ProtoKey key;
    key.shortyIdx = shortyIdx;
    key.returnTypeIdx = returnTypeIdx;
    key.params.reserve(params.size);
    for (ca::u32 i = 0; i < params.size; ++i) {
        key.params.push_back(params.at(i));
    }
    const auto found = pools_.protoIndexByKey.find(key);
    if (found != pools_.protoIndexByKey.end()) {
        return Ok(found->second);
    }
    if (protoIds.size() >= kIdTableLimit) {
        return Err(ReadError::IdTableFull);
    }
    const ca::u32 index = static_cast<ca::u32>(protoIds.size());
    protoIds.push_back(ProtoId{shortyIdx, returnTypeIdx, parametersOff});
    pools_.protoIndexByKey.emplace(std::move(key), index);
    pools_.protoIndexedCount = protoIds.size();
    return Ok(index);
}

Result<ca::u32, ReadError> DexFile::addField(ca::u32 classIdx, ca::u32 typeIdx,
                                             ca::u32 nameIdx)
{
    if (classIdx >= typeIds.size() || typeIdx >= typeIds.size() ||
        nameIdx >= stringIds.size()) {
        return Err(ReadError::BadIndex);
    }
    ensureIdIndexes();
    const ca::u64 key = (static_cast<ca::u64>(classIdx) << 48)
                        | (static_cast<ca::u64>(typeIdx) << 32) | nameIdx;
    const auto found = pools_.fieldIndexByKey.find(key);
    if (found != pools_.fieldIndexByKey.end()) {
        return Ok(found->second);
    }
    if (fieldIds.size() >= kIdTableLimit) {
        return Err(ReadError::IdTableFull);
    }
    const ca::u32 index = static_cast<ca::u32>(fieldIds.size());
    fieldIds.push_back(FieldId{static_cast<ca::u16>(classIdx),
                               static_cast<ca::u16>(typeIdx), nameIdx});
    pools_.fieldIndexByKey.emplace(key, index);
    pools_.fieldIndexedCount = fieldIds.size();
    return Ok(index);
}

Result<ca::u32, ReadError> DexFile::addMethod(ca::u32 classIdx, ca::u32 protoIdx,
                                              ca::u32 nameIdx)
{
    if (classIdx >= typeIds.size() || protoIdx >= protoIds.size() ||
        nameIdx >= stringIds.size()) {
        return Err(ReadError::BadIndex);
    }
    ensureIdIndexes();
    const ca::u64 key = (static_cast<ca::u64>(classIdx) << 48)
                        | (static_cast<ca::u64>(protoIdx) << 32) | nameIdx;
    const auto found = pools_.methodIndexByKey.find(key);
    if (found != pools_.methodIndexByKey.end()) {
        return Ok(found->second);
    }
    if (methodIds.size() >= kIdTableLimit) {
        return Err(ReadError::IdTableFull);
    }
    const ca::u32 index = static_cast<ca::u32>(methodIds.size());
    methodIds.push_back(MethodId{static_cast<ca::u16>(classIdx),
                                 static_cast<ca::u16>(protoIdx), nameIdx});
    pools_.methodIndexByKey.emplace(key, index);
    pools_.methodIndexedCount = methodIds.size();
    return Ok(index);
}

namespace {

/// shorty 字符：对象与数组都记 'L'；描述符非法返回 0。
char shortyCharOf(std::string_view descriptor) noexcept
{
    switch (descriptor.empty() ? '\0' : descriptor[0]) {
        case 'Z':
        case 'B':
        case 'S':
        case 'C':
        case 'I':
        case 'J':
        case 'F':
        case 'D':
        case 'V':
        case 'L':
        case '[':
            return descriptor[0] == '[' ? 'L' : descriptor[0];
        default:
            return '\0';
    }
}

ca::u32 readU32Le(const ca::u8* p) noexcept
{
    return static_cast<ca::u32>(p[0]) | (static_cast<ca::u32>(p[1]) << 8) |
           (static_cast<ca::u32>(p[2]) << 16) | (static_cast<ca::u32>(p[3]) << 24);
}

}   // namespace

Result<ca::u32, ReadError> DexFile::addTypeList(const std::vector<ca::u32>& typeIdxs)
{
    if (typeIdxs.empty()) {
        return Ok(kNoIndex);
    }
    std::vector<ca::u8> encoded;
    encoded.reserve(4u + typeIdxs.size() * 2u);
    encoded.push_back(0);
    encoded.push_back(0);
    encoded.push_back(0);
    encoded.push_back(0);
    for (ca::u32 typeIdx : typeIdxs) {
        if (typeIdx >= typeIds.size()) {
            return Err(ReadError::BadIndex);
        }
        appendU16(encoded, static_cast<ca::u16>(typeIdx));
    }
    encoded[0] = static_cast<ca::u8>(typeIdxs.size() & 0xFFu);
    encoded[1] = static_cast<ca::u8>((typeIdxs.size() >> 8) & 0xFFu);
    encoded[2] = static_cast<ca::u8>((typeIdxs.size() >> 16) & 0xFFu);
    encoded[3] = static_cast<ca::u8>((typeIdxs.size() >> 24) & 0xFFu);
    if (pools_.typeListIndexedCount != pools_.typeLists.size()) {
        pools_.typeListIndexByKey.clear();
        for (ca::u32 i = 0; i < pools_.typeLists.size(); ++i) {
            pools_.typeListIndexByKey.emplace(pools_.typeLists[i], i);
        }
        pools_.typeListIndexedCount = pools_.typeLists.size();
    }
    const auto found = pools_.typeListIndexByKey.find(encoded);
    if (found != pools_.typeListIndexByKey.end()) {
        return Ok(found->second);
    }
    pools_.typeLists.push_back(std::move(encoded));
    pools_.typeListIndexByKey.emplace(pools_.typeLists.back(),
                                static_cast<ca::u32>(pools_.typeLists.size() - 1));
    pools_.typeListIndexedCount = pools_.typeLists.size();
    return Ok(static_cast<ca::u32>(pools_.typeLists.size() - 1));
}

TypeListSpan DexFile::ownedTypeListSpan(ca::u32 index) const noexcept
{
    if (index >= pools_.typeLists.size() || pools_.typeLists[index].size() < 4u) {
        return TypeListSpan{};
    }
    const std::vector<ca::u8>& bytes = pools_.typeLists[index];
    TypeListSpan out;
    out.size = readU32Le(bytes.data());
    out.entries = bytes.data() + 4u;
    return out;
}

Result<ca::u32, ReadError> DexFile::addProtoWithParams(ca::u32 returnTypeIdx,
                                                       const std::vector<ca::u32>& parameters)
{
    if (returnTypeIdx >= typeIds.size()) {
        return Err(ReadError::BadIndex);
    }

    const auto shortyOf = [&](ca::u32 typeIdx,
                              bool allowVoid) -> Result<char, ReadError> {
        Result<jstr::MUtf8StringRef, ReadError> descriptor = typeDescriptor(typeIdx);
        if (descriptor.is_err()) {
            return Err(descriptor.unwrap_err());
        }
        const char ch = shortyCharOf(descriptor.unwrap().as_std_view());
        if (ch == '\0' || (ch == 'V' && !allowVoid)) {
            return Err(ReadError::BadIndex);  // 描述符不是合法类型或参数为 void
        }
        return Ok(ch);
    };

    std::string shorty;
    const Result<char, ReadError> returnChar = shortyOf(returnTypeIdx, true);
    if (returnChar.is_err()) {
        return Err(returnChar.unwrap_err());
    }
    shorty.push_back(returnChar.unwrap());
    for (ca::u32 param : parameters) {
        if (param >= typeIds.size()) {
            return Err(ReadError::BadIndex);
        }
        const Result<char, ReadError> ch = shortyOf(param, false);
        if (ch.is_err()) {
            return Err(ch.unwrap_err());
        }
        shorty.push_back(ch.unwrap());
    }

    // 与既有 proto 按（shorty，返回类型，参数内容）查重；自有与源参数都参与。
    const Result<ca::u32, ReadError> interned = internUtf8(shorty);
    if (interned.is_err()) {
        return Err(interned.unwrap_err());
    }
    ensureIdIndexes();
    ProtoKey key;
    key.shortyIdx = interned.unwrap();
    key.returnTypeIdx = returnTypeIdx;
    key.params = parameters;
    const auto found = pools_.protoIndexByKey.find(key);
    if (found != pools_.protoIndexByKey.end()) {
        return Ok(found->second);
    }
    Result<ca::u32, ReadError> ownedIdx = Ok(kNoIndex);
    if (!parameters.empty()) {
        ownedIdx = addTypeList(parameters);
        if (ownedIdx.is_err()) {
            return Err(ownedIdx.unwrap_err());
        }
    }
    if (protoIds.size() >= kIdTableLimit) {
        return Err(ReadError::IdTableFull);
    }
    const ca::u32 index = static_cast<ca::u32>(protoIds.size());
    protoIds.push_back(ProtoId{interned.unwrap(), returnTypeIdx, 0, ownedIdx.unwrap(),
                               ownedIdx.unwrap() != kNoIndex});
    pools_.protoIndexByKey.emplace(std::move(key), index);
    pools_.protoIndexedCount = protoIds.size();
    return Ok(index);
}

Result<void, ReadError> DexFile::setClassInterfaces(ca::u32 classDefIdx,
                                                    const std::vector<ca::u32>& interfaces)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    const Result<ca::u32, ReadError> owned = addTypeList(interfaces);
    if (owned.is_err()) {
        return Err(owned.unwrap_err());
    }
    ClassDef& def = classDefs[classDefIdx];
    def.ownedInterfacesIdx = owned.unwrap();
    def.ownedInterfaces = def.ownedInterfacesIdx != kNoIndex;
    return Ok();
}

namespace {

bool sameAnnotationValue(const EncodedValue& a, const EncodedValue& b)
{
    if (a.type != b.type || a.valueArg != b.valueArg) {
        return false;
    }
    switch (a.type) {
        case EncodedValueType::Array:
            if (a.array.size() != b.array.size()) {
                return false;
            }
            for (ca::usize i = 0; i < a.array.size(); ++i) {
                if (!sameAnnotationValue(a.array[i], b.array[i])) {
                    return false;
                }
            }
            return true;
        case EncodedValueType::Annotation:
            if (a.annotation == nullptr || b.annotation == nullptr) {
                return a.annotation == b.annotation;
            }
            if (a.annotation->typeIdx != b.annotation->typeIdx ||
                a.annotation->elements.size() != b.annotation->elements.size()) {
                return false;
            }
            for (ca::usize i = 0; i < a.annotation->elements.size(); ++i) {
                const AnnotationElement& ea = a.annotation->elements[i];
                const AnnotationElement& eb = b.annotation->elements[i];
                if (ea.nameIdx != eb.nameIdx || !sameAnnotationValue(ea.value, eb.value)) {
                    return false;
                }
            }
            return true;
        case EncodedValueType::Boolean:
            return a.boolean == b.boolean;
        case EncodedValueType::String:
        case EncodedValueType::MethodType:
        case EncodedValueType::MethodHandle:
        case EncodedValueType::Type:
        case EncodedValueType::Field:
        case EncodedValueType::Method:
        case EncodedValueType::Enum:
            return a.index == b.index;
        case EncodedValueType::Char:
        case EncodedValueType::Float:
        case EncodedValueType::Double:
            return a.bits == b.bits;
        default:
            return a.integer == b.integer;
    }
}

bool sameAnnotation(const AnnotationItem& a, const AnnotationItem& b)
{
    if (a.visibility != b.visibility ||
        a.annotation.typeIdx != b.annotation.typeIdx ||
        a.annotation.elements.size() != b.annotation.elements.size()) {
        return false;
    }
    for (ca::usize i = 0; i < a.annotation.elements.size(); ++i) {
        const AnnotationElement& ea = a.annotation.elements[i];
        const AnnotationElement& eb = b.annotation.elements[i];
        if (ea.nameIdx != eb.nameIdx || !sameAnnotationValue(ea.value, eb.value)) {
            return false;
        }
    }
    return true;
}

/// 索引型 encoded_value 引用的表容量。
ca::u64 indexLimitOf(EncodedValueType type, const DexFile& dex) noexcept
{
    switch (type) {
        case EncodedValueType::String: return dex.stringIds.size();
        case EncodedValueType::Type: return dex.typeIds.size();
        case EncodedValueType::Field:
        case EncodedValueType::Enum: return dex.fieldIds.size();
        case EncodedValueType::Method: return dex.methodIds.size();
        case EncodedValueType::MethodType: return dex.protoIds.size();
        case EncodedValueType::MethodHandle: return dex.methodHandles.size();
        default: return 0;
    }
}

/// 有符号数值的最小编码字节数（1..8）。
ca::u8 minimalSignedWidth(ca::i64 v) noexcept
{
    for (ca::u8 w = 1; w < 8; ++w) {
        const ca::i64 bound = static_cast<ca::i64>(ca::u64{1} << (8u * w - 1u));
        if (v >= -bound && v < bound) {
            return w;
        }
    }
    return 8;
}

/// 无符号数值的最小编码字节数（1..8）。
ca::u8 minimalUnsignedWidth(ca::u64 v) noexcept
{
    ca::u8 w = 1;
    while ((v >> (8u * w)) != 0) {
        ++w;
    }
    return w;
}

/// 浮点/双精度的最小编码字节数：尾部低零字节可省（1..maxBytes）。
ca::u8 minimalFloatWidth(ca::u64 bits, ca::u8 maxBytes) noexcept
{
    ca::u8 width = maxBytes;
    while (width > 1u && (bits & 0xFFu) == 0) {
        bits >>= 8u;
        --width;
    }
    return width;
}

/// 校验新建 encoded_value 引用的表索引，并把载荷宽度归一到最小可用。
/// 布尔按真值置位，Null/Array/Annotation 的 valueArg 清零，数值按最小
/// 有/无符号宽度，浮点按尾部零字节；宽度归一后仍放不下（如 Byte 放大数）
/// 由 writeEncodedValue 拒绝，不做静默截断。
Result<void, ReadError> normalizeEncodedValue(EncodedValue& value, const DexFile& dex)
{
    switch (value.type) {
        case EncodedValueType::Boolean:
            value.valueArg = value.boolean ? 1 : 0;
            return Ok();
        case EncodedValueType::Null:
            value.valueArg = 0;
            return Ok();
        case EncodedValueType::Byte:
        case EncodedValueType::Short:
        case EncodedValueType::Int:
        case EncodedValueType::Long:
            value.valueArg = static_cast<ca::u8>(minimalSignedWidth(value.integer) - 1u);
            return Ok();
        case EncodedValueType::Char:
            value.valueArg =
                static_cast<ca::u8>(minimalUnsignedWidth(value.bits & 0xFFFFu) - 1u);
            return Ok();
        case EncodedValueType::Float:
        case EncodedValueType::Double: {
            const ca::u8 maxBytes = value.type == EncodedValueType::Float ? 4 : 8;
            value.valueArg = static_cast<ca::u8>(minimalFloatWidth(value.bits, maxBytes) - 1u);
            return Ok();
        }
        case EncodedValueType::String:
        case EncodedValueType::Type:
        case EncodedValueType::Field:
        case EncodedValueType::Method:
        case EncodedValueType::Enum:
        case EncodedValueType::MethodType:
        case EncodedValueType::MethodHandle: {
            if (value.index >= indexLimitOf(value.type, dex)) {
                return Err(ReadError::BadIndex);
            }
            value.valueArg = static_cast<ca::u8>(minimalIndexWidth(value.index) - 1u);
            return Ok();
        }
        case EncodedValueType::Array: {
            value.valueArg = 0;
            for (EncodedValue& element : value.array) {
                const Result<void, ReadError> normalized = normalizeEncodedValue(element, dex);
                if (normalized.is_err()) {
                    return normalized;
                }
            }
            return Ok();
        }
        case EncodedValueType::Annotation: {
            value.valueArg = 0;
            if (value.annotation == nullptr) {
                return Ok();
            }
            if (value.annotation->typeIdx >= dex.typeIds.size()) {
                return Err(ReadError::BadIndex);
            }
            for (AnnotationElement& element : value.annotation->elements) {
                if (element.nameIdx >= dex.stringIds.size()) {
                    return Err(ReadError::BadIndex);
                }
                const Result<void, ReadError> normalized =
                    normalizeEncodedValue(element.value, dex);
                if (normalized.is_err()) {
                    return normalized;
                }
            }
            return Ok();
        }
        default:
            return Ok();
    }
}

}   // namespace

Result<ca::u32, ReadError> DexFile::addAnnotationItem(const AnnotationItem& item)
{
    if (item.annotation.typeIdx >= typeIds.size()) {
        return Err(ReadError::BadIndex);
    }
    AnnotationItem normalized = item;
    for (AnnotationElement& element : normalized.annotation.elements) {
        if (element.nameIdx >= stringIds.size()) {
            return Err(ReadError::BadIndex);
        }
        const Result<void, ReadError> value = normalizeEncodedValue(element.value, *this);
        if (value.is_err()) {
            return Err(value.unwrap_err());
        }
    }
    for (ca::u32 i = 0; i < pools_.annotationItems.size(); ++i) {
        if (sameAnnotation(pools_.annotationItems[i], normalized)) {
            return Ok(i);
        }
    }
    pools_.annotationItems.push_back(std::move(normalized));
    return Ok(static_cast<ca::u32>(pools_.annotationItems.size() - 1));
}

const AnnotationItem* DexFile::ownedAnnotationItem(ca::u32 index) const noexcept
{
    if (index >= pools_.annotationItems.size()) {
        return nullptr;
    }
    return &pools_.annotationItems[index];
}

Result<void, ReadError> DexFile::setClassAnnotations(ca::u32 classDefIdx,
                                                     const std::vector<ca::u32>& items)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    for (ca::u32 item : items) {
        if (item >= pools_.annotationItems.size()) {
            return Err(ReadError::BadIndex);
        }
    }
    AnnotationAttachments& attachments = edits_.annotations[classDefIdx];
    attachments.hasClass = true;
    attachments.classItems = items;
    return Ok();
}

namespace {

/// 注解目标成员与池下标的共同校验。
bool validAnnotationHandles(const std::vector<ca::u32>& items, const DexFile& dex)
{
    for (ca::u32 item : items) {
        if (dex.ownedAnnotationItem(item) == nullptr) {
            return false;
        }
    }
    return true;
}

}   // namespace

Result<void, ReadError> DexFile::setFieldAnnotations(ca::u32 classDefIdx, ca::u32 fieldIdx,
                                                     const std::vector<ca::u32>& items)
{
    if (classDefIdx >= classDefs.size() || fieldIdx >= fieldIds.size() ||
        !validAnnotationHandles(items, *this)) {
        return Err(ReadError::BadIndex);
    }
    edits_.annotations[classDefIdx].fields[fieldIdx] = items;
    return Ok();
}

Result<void, ReadError> DexFile::setMethodAnnotations(ca::u32 classDefIdx,
                                                      ca::u32 methodIdx,
                                                      const std::vector<ca::u32>& items)
{
    if (classDefIdx >= classDefs.size() || methodIdx >= methodIds.size() ||
        !validAnnotationHandles(items, *this)) {
        return Err(ReadError::BadIndex);
    }
    edits_.annotations[classDefIdx].methods[methodIdx] = items;
    return Ok();
}

Result<void, ReadError> DexFile::setParameterAnnotations(
    ca::u32 classDefIdx, ca::u32 methodIdx,
    const std::vector<std::vector<ca::u32>>& perParameter)
{
    if (classDefIdx >= classDefs.size() || methodIdx >= methodIds.size()) {
        return Err(ReadError::BadIndex);
    }
    for (const std::vector<ca::u32>& items : perParameter) {
        if (!validAnnotationHandles(items, *this)) {
            return Err(ReadError::BadIndex);
        }
    }
    edits_.annotations[classDefIdx].parameters[methodIdx] = perParameter;
    return Ok();
}

Result<void, ReadError> DexFile::setStaticFieldValue(ca::u32 classDefIdx, ca::u32 fieldIdx,
                                                     const EncodedValue& value)
{
    if (classDefIdx >= classDefs.size() || fieldIdx >= fieldIds.size()) {
        return Err(ReadError::BadIndex);
    }
    const Result<jstr::MUtf8StringRef, ReadError> descriptor = fieldTypeDescriptor(fieldIdx);
    if (descriptor.is_err()) {
        return Err(descriptor.unwrap_err());
    }
    const std::string_view text = descriptor.unwrap().as_std_view();
    bool kindOk = false;
    switch (text.empty() ? '\0' : text[0]) {
        case 'Z': kindOk = value.type == EncodedValueType::Boolean; break;
        case 'B': kindOk = value.type == EncodedValueType::Byte; break;
        case 'S': kindOk = value.type == EncodedValueType::Short; break;
        case 'C': kindOk = value.type == EncodedValueType::Char; break;
        case 'I': kindOk = value.type == EncodedValueType::Int; break;
        case 'J': kindOk = value.type == EncodedValueType::Long; break;
        case 'F': kindOk = value.type == EncodedValueType::Float; break;
        case 'D': kindOk = value.type == EncodedValueType::Double; break;
        case 'L':
        case '[':
            switch (value.type) {
                case EncodedValueType::Null:
                case EncodedValueType::String:
                case EncodedValueType::Type:
                case EncodedValueType::Field:
                case EncodedValueType::Method:
                case EncodedValueType::Enum:
                case EncodedValueType::MethodType:
                case EncodedValueType::MethodHandle:
                case EncodedValueType::Array:
                case EncodedValueType::Annotation:
                    kindOk = true;
                    break;
                default:
                    break;
            }
            break;
        default:
            return Err(ReadError::BadIndex);  // 字段描述符不是合法类型
    }
    if (!kindOk) {
        return Err(ReadError::BadIndex);  // 值类别与字段类型不匹配
    }

    EncodedValue normalized = value;
    const Result<void, ReadError> done = normalizeEncodedValue(normalized, *this);
    if (done.is_err()) {
        return Err(done.unwrap_err());
    }
    edits_.staticValues[classDefIdx][fieldIdx] = std::move(normalized);
    return Ok();
}

void DexFile::refreshInternIndex()
{
    pools_.stringIntern.clear();
    pools_.stringInternedCount = stringIds.size();
    for (ca::u32 i = 0; i < stringIds.size(); ++i) {
        Result<jstr::MUtf8StringRef, ReadError> text = string(i);
        if (text.is_err()) {
            continue;  // 坏条目不能作为查重目标
        }
        pools_.stringIntern.emplace(std::string(text.unwrap().as_std_view()), i);
    }
}

void DexFile::refreshIdIndexes()
{
    pools_.typeIndexByKey.clear();
    pools_.protoIndexByKey.clear();
    pools_.fieldIndexByKey.clear();
    pools_.methodIndexByKey.clear();
    for (ca::u32 i = 0; i < typeIds.size(); ++i) {
        pools_.typeIndexByKey.emplace(typeIds[i].descriptorIdx, i);
    }
    for (ca::u32 i = 0; i < protoIds.size(); ++i) {
        const ProtoId& proto = protoIds[i];
        TypeListSpan span;
        if (proto.ownedParameters) {
            // 池内不存在空列表；entries 为空说明池下标悬垂。
            span = ownedTypeListSpan(proto.ownedParametersIdx);
            if (span.entries == nullptr) {
                continue;  // 池下标悬垂，不作为查重目标
            }
        } else {
            Result<TypeListSpan, ReadError> list = typeList(proto.parametersOff);
            if (list.is_err()) {
                continue;  // 源条目损坏时不作为查重目标
            }
            span = list.unwrap();
        }
        ProtoKey key;
        key.shortyIdx = proto.shortyIdx;
        key.returnTypeIdx = proto.returnTypeIdx;
        key.params.reserve(span.size);
        for (ca::u32 j = 0; j < span.size; ++j) {
            key.params.push_back(span.at(j));
        }
        pools_.protoIndexByKey.emplace(std::move(key), i);
    }
    for (ca::u32 i = 0; i < fieldIds.size(); ++i) {
        const FieldId& field = fieldIds[i];
        const ca::u64 key = (static_cast<ca::u64>(field.classIdx) << 48)
                            | (static_cast<ca::u64>(field.typeIdx) << 32) | field.nameIdx;
        pools_.fieldIndexByKey.emplace(key, i);
    }
    for (ca::u32 i = 0; i < methodIds.size(); ++i) {
        const MethodId& method = methodIds[i];
        const ca::u64 key = (static_cast<ca::u64>(method.classIdx) << 48)
                            | (static_cast<ca::u64>(method.protoIdx) << 32)
                            | method.nameIdx;
        pools_.methodIndexByKey.emplace(key, i);
    }
    pools_.typeIndexedCount = typeIds.size();
    pools_.protoIndexedCount = protoIds.size();
    pools_.fieldIndexedCount = fieldIds.size();
    pools_.methodIndexedCount = methodIds.size();
}

void DexFile::ensureIdIndexes()
{
    if (pools_.typeIndexedCount != typeIds.size() || pools_.protoIndexedCount != protoIds.size()
        || pools_.fieldIndexedCount != fieldIds.size()
        || pools_.methodIndexedCount != methodIds.size()) {
        refreshIdIndexes();
    }
}

const jstr::MUtf8StringRef* DexFile::peekString(ca::u32 index) const noexcept
{
    if (index >= caches_.strings.size()) {
        return nullptr;
    }
    const LazyString& slot = caches_.strings[index];
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
    if (offset >= pools_.sourceBytes.len()) {
        return Err(ReadError::BadTableSpan);
    }

    Result<Reader, ReadError> reader = Reader::at(pools_.sourceBytes, offset);
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
    if (bytes > static_cast<ca::u64>(pools_.sourceBytes.len() - offset)) {
        return Err(ReadError::BadTableSpan);
    }

    TypeListSpan out;
    out.raw = ByteSpan{offset, static_cast<ca::u32>(bytes)};
    out.size = count;
    out.entries = pools_.sourceBytes.as_ptr() + offset + 4;
    return Ok(out);
}

Result<TypeListSpan, ReadError> DexFile::protoParameters(ca::u32 protoIdx)
{
    if (protoIdx >= protoIds.size()) {
        return Err(ReadError::BadIndex);
    }
    const ProtoId& proto = protoIds[protoIdx];
    if (proto.ownedParameters) {
        const TypeListSpan span = ownedTypeListSpan(proto.ownedParametersIdx);
        if (span.entries == nullptr) {
            return Err(ReadError::BadIndex);  // 池下标悬垂
        }
        return Ok(span);
    }
    return typeList(proto.parametersOff);
}

Result<TypeListSpan, ReadError> DexFile::interfaces(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    const ClassDef& def = classDefs[classDefIdx];
    if (def.ownedInterfaces) {
        const TypeListSpan span = ownedTypeListSpan(def.ownedInterfacesIdx);
        if (span.entries == nullptr) {
            return Err(ReadError::BadIndex);  // 池下标悬垂
        }
        return Ok(span);
    }
    return typeList(def.interfacesOff);
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
    if (caches_.classDatas.size() != classDefs.size()) {
        caches_.classDatas.resize(classDefs.size());
    }

    LazyClassData& slot = caches_.classDatas[classDefIdx];
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
    if (classDefIdx >= caches_.classDatas.size()) {
        return nullptr;
    }
    const LazyClassData& slot = caches_.classDatas[classDefIdx];
    return slot.state == LazyClassData::State::Decoded ? slot.data.get() : nullptr;
}

Result<std::unique_ptr<ClassData>, ReadError> DexFile::decodeClassData(ca::u32 offset)
{
    Result<ClassData, ReadError> parsed = parseClassData(source(), offset, fieldCount(), methodCount());
    if (parsed.is_err()) {
        return Err(parsed.unwrap_err());
    }
    std::unique_ptr<ClassData> data = std::make_unique<ClassData>(std::move(parsed).unwrap());
    return Ok(std::move(data));
}

Result<const CodeItem*, ReadError> DexFile::codeItem(ca::u32 codeOff)
{
    if (codeOff == 0) {
        return Ok(static_cast<const CodeItem*>(nullptr));
    }

    const auto it = caches_.code.find(codeOff);
    if (it != caches_.code.end()) {
        return Ok(static_cast<const CodeItem*>(it->second.get()));
    }
    const auto failed = caches_.codeFailures.find(codeOff);
    if (failed != caches_.codeFailures.end()) {
        return Err(failed->second);
    }

    Result<std::unique_ptr<CodeItem>, ReadError> decoded = decodeCodeItem(codeOff);
    if (decoded.is_err()) {
        const ReadError error = decoded.unwrap_err();
        caches_.codeFailures.emplace(codeOff, error);
        return Err(error);
    }

    std::unique_ptr<CodeItem> item = std::move(decoded).unwrap();
    const CodeItem* view = item.get();
    caches_.code.emplace(codeOff, std::move(item));
    return Ok(view);
}

const CodeItem* DexFile::peekCodeItem(ca::u32 codeOff) const noexcept
{
    const auto it = caches_.code.find(codeOff);
    return it == caches_.code.end() ? nullptr : it->second.get();
}

Result<std::unique_ptr<CodeItem>, ReadError> DexFile::decodeCodeItem(ca::u32 offset)
{
    Result<CodeItem, ReadError> parsed = parseCodeItem(source(), offset, typeCount(), &diag_);
    if (parsed.is_err()) {
        return Err(parsed.unwrap_err());
    }
    return Ok(std::make_unique<CodeItem>(std::move(parsed).unwrap()));
}

template <typename T>
Result<const T*, ReadError> DexFile::decodeLazy(
    std::unordered_map<ca::u32, LazyItem<T>>& cache, ca::u32 offset,
    Result<T, ReadError> (*decode)(ByteSlice, ca::u32))
{
    if (offset == 0) {
        return Ok(static_cast<const T*>(nullptr));
    }

    const auto found = cache.find(offset);
    if (found != cache.end()) {
        if (found->second.state == LazyItem<T>::State::Decoded) {
            return Ok(static_cast<const T*>(found->second.item.get()));
        }
        if (found->second.state == LazyItem<T>::State::Failed) {
            return Err(found->second.error);
        }
    }

    Result<T, ReadError> parsed = decode(source(), offset);
    LazyItem<T>& slot = cache[offset];
    if (parsed.is_err()) {
        slot.state = LazyItem<T>::State::Failed;
        slot.error = parsed.unwrap_err();
        return Err(slot.error);
    }
    slot.item = std::make_unique<T>(std::move(parsed).unwrap());
    slot.state = LazyItem<T>::State::Decoded;
    return Ok(static_cast<const T*>(slot.item.get()));
}

Result<const AnnotationsDirectory*, ReadError> DexFile::annotationsDirectory(ca::u32 offset)
{
    return decodeLazy(caches_.annotationsDirectory, offset, &readAnnotationsDirectory);
}

Result<const AnnotationSetItem*, ReadError> DexFile::annotationSet(ca::u32 offset)
{
    return decodeLazy(caches_.annotationSet, offset, &readAnnotationSet);
}

Result<const AnnotationSetRefList*, ReadError> DexFile::annotationSetRefList(ca::u32 offset)
{
    return decodeLazy(caches_.annotationSetRef, offset, &readAnnotationSetRefList);
}

Result<const AnnotationItem*, ReadError> DexFile::annotationItem(ca::u32 offset)
{
    return decodeLazy(caches_.annotationItem, offset, &readAnnotationItem);
}

Result<const EncodedArrayItem*, ReadError> DexFile::encodedArray(ca::u32 offset)
{
    return decodeLazy(caches_.encodedArray, offset, &readEncodedArrayItem);
}

Result<const AnnotationsDirectory*, ReadError> DexFile::classAnnotations(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    return annotationsDirectory(classDefs[classDefIdx].annotationsOff);
}

Result<const EncodedArrayItem*, ReadError> DexFile::staticValues(ca::u32 classDefIdx)
{
    if (classDefIdx >= classDefs.size()) {
        return Err(ReadError::BadIndex);
    }
    return encodedArray(classDefs[classDefIdx].staticValuesOff);
}

Result<const DebugInfo*, ReadError> DexFile::debugInfo(ca::u32 offset)
{
    return decodeLazy(caches_.debugInfo, offset, &readDebugInfo);
}

Result<const EncodedArrayItem*, ReadError> DexFile::callSiteValues(ca::u32 index)
{
    if (index >= callSites.size()) {
        return Err(ReadError::BadIndex);
    }
    return encodedArray(callSites[index].callSiteOff);
}

}   // namespace dex::core
