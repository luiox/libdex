/// @file        annotation.cpp
/// @brief       注解族数据条目的结构解码。
#include "dex/core/annotation.hpp"

#include <utility>

#include "dex/core/leb128.hpp"

namespace dex::core {

namespace {

Result<Reader, ReadError> readerAt(ByteSlice source, ca::u32 offset)
{
    const ca::core::Bytes bytes = ca::core::Bytes::from_static(source.data(), source.size());
    return Reader::at(bytes, offset);
}

void appendU32(std::vector<ca::u8>& out, ca::u32 value)
{
    for (ca::u32 i = 0; i < 4; ++i) {
        out.push_back(static_cast<ca::u8>(value >> (8u * i)));
    }
}

}   // namespace

Result<AnnotationItem, ReadError> readAnnotationItem(ByteSlice source, ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u8, ReadError> visibility = cur.u8();
    if (visibility.is_err()) {
        return Err(visibility.unwrap_err());
    }

    AnnotationItem item;
    item.visibility = visibility.unwrap();
    Result<EncodedAnnotation, ReadError> annotation = readEncodedAnnotation(cur);
    if (annotation.is_err()) {
        return Err(annotation.unwrap_err());
    }
    item.annotation = std::move(annotation).unwrap();
    item.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(item));
}

Result<AnnotationSetItem, ReadError> readAnnotationSet(ByteSlice source, ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u32, ReadError> count = cur.u32();
    if (count.is_err()) {
        return Err(count.unwrap_err());
    }
    if (count.unwrap() > cur.remaining() / 4u) {
        return Err(ReadError::Truncated);
    }

    AnnotationSetItem item;
    item.annotationOffs.reserve(count.unwrap());
    for (ca::u32 i = 0; i < count.unwrap(); ++i) {
        const Result<ca::u32, ReadError> entry = cur.u32();
        if (entry.is_err()) {
            return Err(entry.unwrap_err());
        }
        item.annotationOffs.push_back(entry.unwrap());
    }
    item.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(item));
}

Result<AnnotationSetRefList, ReadError> readAnnotationSetRefList(ByteSlice source, ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u32, ReadError> count = cur.u32();
    if (count.is_err()) {
        return Err(count.unwrap_err());
    }
    if (count.unwrap() > cur.remaining() / 4u) {
        return Err(ReadError::Truncated);
    }

    AnnotationSetRefList item;
    item.annotationSetOffs.reserve(count.unwrap());
    for (ca::u32 i = 0; i < count.unwrap(); ++i) {
        const Result<ca::u32, ReadError> entry = cur.u32();
        if (entry.is_err()) {
            return Err(entry.unwrap_err());
        }
        item.annotationSetOffs.push_back(entry.unwrap());
    }
    item.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(item));
}

Result<AnnotationsDirectory, ReadError> readAnnotationsDirectory(ByteSlice source,
                                                                ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u32, ReadError> classOff = cur.u32();
    const Result<ca::u32, ReadError> fieldCount = cur.u32();
    const Result<ca::u32, ReadError> methodCount = cur.u32();
    const Result<ca::u32, ReadError> parameterCount = cur.u32();
    if (classOff.is_err() || fieldCount.is_err() || methodCount.is_err() ||
        parameterCount.is_err()) {
        return Err(ReadError::Truncated);
    }

    const ca::u64 total = static_cast<ca::u64>(fieldCount.unwrap()) +
                          static_cast<ca::u64>(methodCount.unwrap()) +
                          static_cast<ca::u64>(parameterCount.unwrap());
    if (total > cur.remaining() / 8u) {
        return Err(ReadError::Truncated);
    }

    AnnotationsDirectory directory;
    directory.classAnnotationsOff = classOff.unwrap();

    const auto readEntries = [&cur](ca::u32 count,
                                    std::vector<AnnotationsDirectoryEntry>& out)
        -> Result<void, ReadError> {
        out.reserve(count);
        for (ca::u32 i = 0; i < count; ++i) {
            const Result<ca::u32, ReadError> memberIdx = cur.u32();
            const Result<ca::u32, ReadError> annotationsOff = cur.u32();
            if (memberIdx.is_err() || annotationsOff.is_err()) {
                return Err(ReadError::Truncated);
            }
            out.push_back(AnnotationsDirectoryEntry{memberIdx.unwrap(),
                                                    annotationsOff.unwrap()});
        }
        return Ok();
    };

    const Result<void, ReadError> fields =
        readEntries(fieldCount.unwrap(), directory.fieldAnnotations);
    if (fields.is_err()) {
        return Err(fields.unwrap_err());
    }
    const Result<void, ReadError> methods =
        readEntries(methodCount.unwrap(), directory.methodAnnotations);
    if (methods.is_err()) {
        return Err(methods.unwrap_err());
    }
    const Result<void, ReadError> parameters =
        readEntries(parameterCount.unwrap(), directory.parameterAnnotations);
    if (parameters.is_err()) {
        return Err(parameters.unwrap_err());
    }

    directory.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(directory));
}

Result<EncodedArrayItem, ReadError> readEncodedArrayItem(ByteSlice source, ca::u32 offset)
{
    Result<Reader, ReadError> reader = readerAt(source, offset);
    if (reader.is_err()) {
        return Err(reader.unwrap_err());
    }
    Reader cur = std::move(reader).unwrap();

    const Result<ca::u32, ReadError> size = readUleb128(cur);
    if (size.is_err()) {
        return Err(size.unwrap_err());
    }
    const ca::u32 count = size.unwrap();
    // 每个元素至少一个 header 字节。
    if (count > cur.remaining()) {
        return Err(ReadError::Truncated);
    }

    EncodedArrayItem item;
    item.values.reserve(count);
    for (ca::u32 i = 0; i < count; ++i) {
        Result<EncodedValue, ReadError> value = readEncodedValue(cur);
        if (value.is_err()) {
            return Err(value.unwrap_err());
        }
        item.values.push_back(std::move(value).unwrap());
    }
    item.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(item));
}

Result<std::vector<ca::u8>, WriteError> writeAnnotationItem(const AnnotationItem& item)
{
    std::vector<ca::u8> out;
    out.push_back(item.visibility);
    const Result<std::vector<ca::u8>, WriteError> body =
        writeEncodedAnnotation(item.annotation);
    if (body.is_err()) {
        return Err(body.unwrap_err());
    }
    const std::vector<ca::u8>& bytes = body.unwrap();
    out.insert(out.end(), bytes.begin(), bytes.end());
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeAnnotationSet(const AnnotationSetItem& item)
{
    std::vector<ca::u8> out;
    appendU32(out, static_cast<ca::u32>(item.annotationOffs.size()));
    for (ca::u32 offset : item.annotationOffs) {
        appendU32(out, offset);
    }
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeAnnotationSetRefList(
    const AnnotationSetRefList& item)
{
    std::vector<ca::u8> out;
    appendU32(out, static_cast<ca::u32>(item.annotationSetOffs.size()));
    for (ca::u32 offset : item.annotationSetOffs) {
        appendU32(out, offset);
    }
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeAnnotationsDirectory(
    const AnnotationsDirectory& item)
{
    std::vector<ca::u8> out;
    appendU32(out, item.classAnnotationsOff);
    appendU32(out, static_cast<ca::u32>(item.fieldAnnotations.size()));
    appendU32(out, static_cast<ca::u32>(item.methodAnnotations.size()));
    appendU32(out, static_cast<ca::u32>(item.parameterAnnotations.size()));

    const auto appendEntries = [&out](const std::vector<AnnotationsDirectoryEntry>& entries) {
        for (const AnnotationsDirectoryEntry& entry : entries) {
            appendU32(out, entry.memberIdx);
            appendU32(out, entry.annotationsOff);
        }
    };
    appendEntries(item.fieldAnnotations);
    appendEntries(item.methodAnnotations);
    appendEntries(item.parameterAnnotations);
    return Ok(std::move(out));
}

Result<std::vector<ca::u8>, WriteError> writeEncodedArrayItem(const EncodedArrayItem& item)
{
    return writeEncodedArray(item.values);
}

const char* to_string(AnnotationVisibility visibility) noexcept
{
    switch (visibility) {
        case AnnotationVisibility::Build: return "build";
        case AnnotationVisibility::Runtime: return "runtime";
        case AnnotationVisibility::System: return "system";
    }
    return "unknown";
}

}   // namespace dex::core
