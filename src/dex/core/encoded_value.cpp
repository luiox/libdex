/// @file        encoded_value.cpp
/// @brief       encoded_value / encoded_annotation 读取实现。
#include "dex/core/encoded_value.hpp"

#include <utility>

#include "dex/core/leb128.hpp"

namespace dex::core {

namespace {

Result<ca::u64, ReadError> readLittleEndian(Reader& cur, ca::u32 byteCount) noexcept
{
    ca::u64 value = 0;
    for (ca::u32 i = 0; i < byteCount; ++i) {
        const Result<ca::u8, ReadError> byte = cur.u8();
        if (byte.is_err()) {
            return Err(byte.unwrap_err());
        }
        value |= static_cast<ca::u64>(byte.unwrap()) << (8u * i);
    }
    return Ok(value);
}

ca::i64 signExtendTo64(ca::u64 value, ca::u32 bits) noexcept
{
    if (bits >= 64) {
        return static_cast<ca::i64>(value);
    }
    const ca::u64 sign = ca::u64{1} << (bits - 1);
    return static_cast<ca::i64>((value ^ sign) - sign);
}

bool fitsSigned(ca::i64 value, ca::u32 bits) noexcept
{
    if (bits >= 64) {
        return true;
    }
    const ca::i64 min = -(ca::i64{1} << (bits - 1));
    const ca::i64 max = (ca::i64{1} << (bits - 1)) - 1;
    return value >= min && value <= max;
}

bool fitsUnsigned(ca::u64 value, ca::u32 bits) noexcept
{
    if (bits >= 64) {
        return true;
    }
    return value <= (ca::u64{1} << bits) - 1;
}

void appendLittleEndian(std::vector<ca::u8>& out, ca::u64 value, ca::u32 byteCount)
{
    for (ca::u32 i = 0; i < byteCount; ++i) {
        out.push_back(static_cast<ca::u8>(value >> (8u * i)));
    }
}

void appendUleb128(std::vector<ca::u8>& out, ca::u32 value)
{
    do {
        ca::u8 byte = static_cast<ca::u8>(value & 0x7Fu);
        value >>= 7u;
        if (value != 0) {
            byte |= 0x80u;
        }
        out.push_back(byte);
    } while (value != 0);
}

Result<void, WriteError> writeValue(const EncodedValue& value, ca::u32 depth,
                                    std::vector<ca::u8>& out);

Result<void, WriteError> writeAnnotation(const EncodedAnnotation& annotation,
                                         ca::u32 depth, std::vector<ca::u8>& out)
{
    if (depth >= kMaxValueDepth) {
        return Err(WriteError::Unencodable);
    }
    appendUleb128(out, annotation.typeIdx);
    appendUleb128(out, static_cast<ca::u32>(annotation.elements.size()));
    for (const AnnotationElement& element : annotation.elements) {
        appendUleb128(out, element.nameIdx);
        const Result<void, WriteError> written = writeValue(element.value, depth + 1, out);
        if (written.is_err()) {
            return Err(written.unwrap_err());
        }
    }
    return Ok();
}

Result<void, WriteError> writeValue(const EncodedValue& value, ca::u32 depth,
                                    std::vector<ca::u8>& out)
{
    const ca::u32 byteCount = static_cast<ca::u32>(value.valueArg) + 1u;
    out.push_back(value.header());

    switch (value.type) {
    case EncodedValueType::Byte:
    case EncodedValueType::Short:
    case EncodedValueType::Int:
    case EncodedValueType::Long: {
        ca::u32 maxBytes = 1;
        if (value.type == EncodedValueType::Short) {
            maxBytes = 2;
        } else if (value.type == EncodedValueType::Int) {
            maxBytes = 4;
        } else if (value.type == EncodedValueType::Long) {
            maxBytes = 8;
        }
        if (byteCount > maxBytes || !fitsSigned(value.integer, byteCount * 8u)) {
            return Err(WriteError::Unencodable);
        }
        appendLittleEndian(out, static_cast<ca::u64>(value.integer), byteCount);
        return Ok();
    }
    case EncodedValueType::Char:
        if (byteCount > 2 || !fitsUnsigned(value.bits, byteCount * 8u)) {
            return Err(WriteError::Unencodable);
        }
        appendLittleEndian(out, value.bits, byteCount);
        return Ok();
    case EncodedValueType::Float:
    case EncodedValueType::Double: {
        const ca::u32 maxBytes = value.type == EncodedValueType::Float ? 4u : 8u;
        if (byteCount > maxBytes) {
            return Err(WriteError::Unencodable);
        }
        const ca::u32 shift = (maxBytes - byteCount) * 8u;
        if (shift != 0 && (value.bits & ((ca::u64{1} << shift) - 1u)) != 0) {
            return Err(WriteError::Unencodable);
        }
        appendLittleEndian(out, value.bits >> shift, byteCount);
        return Ok();
    }
    case EncodedValueType::MethodType:
    case EncodedValueType::MethodHandle:
    case EncodedValueType::String:
    case EncodedValueType::Type:
    case EncodedValueType::Field:
    case EncodedValueType::Method:
    case EncodedValueType::Enum:
        if (byteCount > 4 || !fitsUnsigned(value.index, byteCount * 8u)) {
            return Err(WriteError::Unencodable);
        }
        appendLittleEndian(out, value.index, byteCount);
        return Ok();
    case EncodedValueType::Array:
        if (value.valueArg != 0 || depth >= kMaxValueDepth) {
            return Err(WriteError::Unencodable);
        }
        appendUleb128(out, static_cast<ca::u32>(value.array.size()));
        for (const EncodedValue& element : value.array) {
            const Result<void, WriteError> written = writeValue(element, depth + 1, out);
            if (written.is_err()) {
                return Err(written.unwrap_err());
            }
        }
        return Ok();
    case EncodedValueType::Annotation:
        if (value.valueArg != 0 || value.annotation == nullptr) {
            return Err(WriteError::Unencodable);
        }
        return writeAnnotation(*value.annotation, depth + 1, out);
    case EncodedValueType::Null:
        if (value.valueArg != 0) {
            return Err(WriteError::Unencodable);
        }
        return Ok();
    case EncodedValueType::Boolean:
        if (value.valueArg > 1 || value.boolean != (value.valueArg != 0)) {
            return Err(WriteError::Unencodable);
        }
        return Ok();
    }
    return Err(WriteError::Unencodable);
}

}   // namespace

EncodedValue::EncodedValue(const EncodedValue& other)
    : type(other.type), valueArg(other.valueArg), integer(other.integer), bits(other.bits),
      index(other.index), boolean(other.boolean), array(other.array)
{
    if (other.annotation != nullptr) {
        annotation = std::make_unique<EncodedAnnotation>(*other.annotation);
    }
}

EncodedValue& EncodedValue::operator=(const EncodedValue& other)
{
    if (this != &other) {
        type = other.type;
        valueArg = other.valueArg;
        integer = other.integer;
        bits = other.bits;
        index = other.index;
        boolean = other.boolean;
        array = other.array;
        annotation = other.annotation != nullptr
                         ? std::make_unique<EncodedAnnotation>(*other.annotation)
                         : nullptr;
    }
    return *this;
}

EncodedValue::EncodedValue(EncodedValue&&) noexcept = default;
EncodedValue& EncodedValue::operator=(EncodedValue&&) noexcept = default;
EncodedValue::~EncodedValue() = default;

Result<EncodedValue, ReadError> readEncodedValue(Reader& cur, ca::u32 depth) noexcept
{
    const Result<ca::u8, ReadError> headerResult = cur.u8();
    if (headerResult.is_err()) {
        return Err(headerResult.unwrap_err());
    }
    const ca::u8 header = headerResult.unwrap();
    const auto type = static_cast<EncodedValueType>(header & 0x1Fu);
    const ca::u32 valueArg = header >> 5;

    EncodedValue value;
    value.type = type;
    value.valueArg = static_cast<ca::u8>(valueArg);

    switch (type) {
    case EncodedValueType::Byte: {
        if (valueArg != 0) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u64, ReadError> raw = readLittleEndian(cur, 1);
        if (raw.is_err()) {
            return Err(raw.unwrap_err());
        }
        value.integer = signExtendTo64(raw.unwrap(), 8);
        return Ok(std::move(value));
    }
    case EncodedValueType::Short:
    case EncodedValueType::Int:
    case EncodedValueType::Long: {
        const ca::u32 maxBytes = type == EncodedValueType::Short ? 2u
                                 : type == EncodedValueType::Int ? 4u
                                                                 : 8u;
        const ca::u32 byteCount = valueArg + 1;
        if (byteCount > maxBytes) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u64, ReadError> raw = readLittleEndian(cur, byteCount);
        if (raw.is_err()) {
            return Err(raw.unwrap_err());
        }
        value.integer = signExtendTo64(raw.unwrap(), byteCount * 8u);
        return Ok(std::move(value));
    }
    case EncodedValueType::Char: {
        const ca::u32 byteCount = valueArg + 1;
        if (byteCount > 2) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u64, ReadError> raw = readLittleEndian(cur, byteCount);
        if (raw.is_err()) {
            return Err(raw.unwrap_err());
        }
        value.bits = raw.unwrap();
        return Ok(std::move(value));
    }
    case EncodedValueType::Float:
    case EncodedValueType::Double: {
        const ca::u32 maxBytes = type == EncodedValueType::Float ? 4u : 8u;
        const ca::u32 byteCount = valueArg + 1;
        if (byteCount > maxBytes) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u64, ReadError> raw = readLittleEndian(cur, byteCount);
        if (raw.is_err()) {
            return Err(raw.unwrap_err());
        }
        // 浮点位模式的尾随零字节省略，读回时补到宽度右侧。
        value.bits = raw.unwrap() << ((maxBytes - byteCount) * 8u);
        return Ok(std::move(value));
    }
    case EncodedValueType::MethodType:
    case EncodedValueType::MethodHandle:
    case EncodedValueType::String:
    case EncodedValueType::Type:
    case EncodedValueType::Field:
    case EncodedValueType::Method:
    case EncodedValueType::Enum: {
        // 引用类索引是 value_arg+1 个字节的小端零扩展整数，不是 ULEB128。
        const ca::u32 byteCount = valueArg + 1;
        if (byteCount > 4) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u64, ReadError> raw = readLittleEndian(cur, byteCount);
        if (raw.is_err()) {
            return Err(raw.unwrap_err());
        }
        value.index = static_cast<ca::u32>(raw.unwrap());
        return Ok(std::move(value));
    }
    case EncodedValueType::Array: {
        if (valueArg != 0) {
            return Err(ReadError::BadEncodedValue);
        }
        if (depth >= kMaxValueDepth) {
            return Err(ReadError::BadEncodedValue);
        }
        const Result<ca::u32, ReadError> size = readUleb128(cur);
        if (size.is_err()) {
            return Err(size.unwrap_err());
        }
        const ca::u32 count = size.unwrap();
        // 每个元素至少一个 header 字节。
        if (count > cur.remaining()) {
            return Err(ReadError::Truncated);
        }
        value.array.reserve(count);
        for (ca::u32 i = 0; i < count; ++i) {
            Result<EncodedValue, ReadError> element = readEncodedValue(cur, depth + 1);
            if (element.is_err()) {
                return Err(element.unwrap_err());
            }
            value.array.push_back(std::move(element).unwrap());
        }
        return Ok(std::move(value));
    }
    case EncodedValueType::Annotation: {
        if (valueArg != 0) {
            return Err(ReadError::BadEncodedValue);
        }
        if (depth >= kMaxValueDepth) {
            return Err(ReadError::BadEncodedValue);
        }
        Result<EncodedAnnotation, ReadError> annotation =
            readEncodedAnnotation(cur, depth + 1);
        if (annotation.is_err()) {
            return Err(annotation.unwrap_err());
        }
        value.annotation = std::make_unique<EncodedAnnotation>(std::move(annotation).unwrap());
        return Ok(std::move(value));
    }
    case EncodedValueType::Null:
        if (valueArg != 0) {
            return Err(ReadError::BadEncodedValue);
        }
        return Ok(std::move(value));
    case EncodedValueType::Boolean:
        if (valueArg > 1) {
            return Err(ReadError::BadEncodedValue);
        }
        value.boolean = valueArg != 0;
        return Ok(std::move(value));
    }

    return Err(ReadError::BadEncodedValue);
}

Result<EncodedAnnotation, ReadError> readEncodedAnnotation(Reader& cur, ca::u32 depth) noexcept
{
    if (depth >= kMaxValueDepth) {
        return Err(ReadError::BadEncodedValue);
    }

    const Result<ca::u32, ReadError> typeIndex = readUleb128(cur);
    if (typeIndex.is_err()) {
        return Err(typeIndex.unwrap_err());
    }
    const Result<ca::u32, ReadError> size = readUleb128(cur);
    if (size.is_err()) {
        return Err(size.unwrap_err());
    }
    const ca::u32 count = size.unwrap();
    // 每个元素至少一个 name uleb 和一个 value header 字节。
    if (count > cur.remaining() / 2u) {
        return Err(ReadError::Truncated);
    }

    EncodedAnnotation annotation;
    annotation.typeIdx = typeIndex.unwrap();
    annotation.elements.reserve(count);
    for (ca::u32 i = 0; i < count; ++i) {
        const Result<ca::u32, ReadError> name = readUleb128(cur);
        if (name.is_err()) {
            return Err(name.unwrap_err());
        }
        Result<EncodedValue, ReadError> value = readEncodedValue(cur, depth);
        if (value.is_err()) {
            return Err(value.unwrap_err());
        }
        annotation.elements.push_back(AnnotationElement{name.unwrap(), std::move(value).unwrap()});
    }
    return Ok(std::move(annotation));
}

Result<std::vector<ca::u8>, WriteError> writeEncodedValue(const EncodedValue& value)
{
    std::vector<ca::u8> out;
    const Result<void, WriteError> written = writeValue(value, 0, out);
    if (written.is_err()) {
        return Err(written.unwrap_err());
    }
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeEncodedArray(
    const std::vector<EncodedValue>& values)
{
    std::vector<ca::u8> out;
    appendUleb128(out, static_cast<ca::u32>(values.size()));
    for (const EncodedValue& value : values) {
        const Result<void, WriteError> written = writeValue(value, 1, out);
        if (written.is_err()) {
            return Err(written.unwrap_err());
        }
    }
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeEncodedAnnotation(
    const EncodedAnnotation& annotation)
{
    std::vector<ca::u8> out;
    const Result<void, WriteError> written = writeAnnotation(annotation, 0, out);
    if (written.is_err()) {
        return Err(written.unwrap_err());
    }
    return Ok(std::move(out));
}

const char* to_string(EncodedValueType type) noexcept
{
    switch (type) {
    case EncodedValueType::Byte:
        return "byte";
    case EncodedValueType::Short:
        return "short";
    case EncodedValueType::Char:
        return "char";
    case EncodedValueType::Int:
        return "int";
    case EncodedValueType::Long:
        return "long";
    case EncodedValueType::Float:
        return "float";
    case EncodedValueType::Double:
        return "double";
    case EncodedValueType::MethodType:
        return "method_type";
    case EncodedValueType::MethodHandle:
        return "method_handle";
    case EncodedValueType::String:
        return "string";
    case EncodedValueType::Type:
        return "type";
    case EncodedValueType::Field:
        return "field";
    case EncodedValueType::Method:
        return "method";
    case EncodedValueType::Enum:
        return "enum";
    case EncodedValueType::Array:
        return "array";
    case EncodedValueType::Annotation:
        return "annotation";
    case EncodedValueType::Null:
        return "null";
    case EncodedValueType::Boolean:
        return "boolean";
    }
    return "unknown";
}

}   // namespace dex::core
