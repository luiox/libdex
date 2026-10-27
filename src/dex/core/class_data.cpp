/// @file        class_data.cpp
/// @brief       class_data_item 的结构解码与精确重编码实现。
#include "dex/core/class_data.hpp"

#include <vector>

#include "dex/core/leb128.hpp"
#include "dex/core/reader.hpp"

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

template <typename Entry, typename IndexOf>
bool indicesStrictlyIncreasing(const std::vector<Entry>& entries, IndexOf indexOf) noexcept
{
    for (ca::usize i = 1; i < entries.size(); ++i) {
        if (indexOf(entries[i]) <= indexOf(entries[i - 1])) {
            return false;
        }
    }
    return true;
}

}   // namespace

Result<ClassData, ReadError> parseClassData(ByteSlice source, ca::u32 offset,
                                            ca::u32 fieldLimit, ca::u32 methodLimit)
{
    if (offset >= source.size()) {
        return Err(ReadError::BadClassData);
    }

    const ca::core::Bytes bytes = ca::core::Bytes::from_static(source.data(), source.size());
    Result<Reader, ReadError> reader = Reader::at(bytes, offset);
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
    if (fieldTotal > fieldLimit || methodTotal > methodLimit) {
        return Err(ReadError::BadClassData);
    }

    // 每条 encoded_field 至少 2 字节、encoded_method 至少 3 字节；先按剩余
    // 字节数封顶，避免小文件里伪造大计数触发放大分配。
    const ca::u64 minBytes = static_cast<ca::u64>(counts[0]) * 2u + counts[1] * 2u +
                             static_cast<ca::u64>(counts[2]) * 3u + counts[3] * 3u;
    if (minBytes > cur.remaining()) {
        return Err(ReadError::BadClassData);
    }

    ClassData data;

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

    if (readFields(counts[0], data.staticFields).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readFields(counts[1], data.instanceFields).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readMethods(counts[2], data.directMethods).is_err()) {
        return Err(ReadError::BadClassData);
    }
    if (readMethods(counts[3], data.virtualMethods).is_err()) {
        return Err(ReadError::BadClassData);
    }

    data.raw = ByteSpan{offset, static_cast<ca::u32>(cur.pos() - offset)};
    return Ok(std::move(data));
}

Result<std::vector<ca::u8>, WriteError> writeClassData(const ClassData& data)
{
    if (data.staticFields.size() > 0xFFFFFFFFu ||
        data.instanceFields.size() > 0xFFFFFFFFu ||
        data.directMethods.size() > 0xFFFFFFFFu ||
        data.virtualMethods.size() > 0xFFFFFFFFu) {
        return Err(WriteError::Unencodable);
    }
    if (!indicesStrictlyIncreasing(data.staticFields,
                                   [](const EncodedField& f) { return f.fieldIndex; }) ||
        !indicesStrictlyIncreasing(data.instanceFields,
                                   [](const EncodedField& f) { return f.fieldIndex; }) ||
        !indicesStrictlyIncreasing(data.directMethods,
                                   [](const EncodedMethod& m) { return m.methodIndex; }) ||
        !indicesStrictlyIncreasing(data.virtualMethods,
                                   [](const EncodedMethod& m) { return m.methodIndex; })) {
        return Err(WriteError::Unencodable);
    }

    std::vector<ca::u8> out;
    writeUleb128(out, static_cast<ca::u32>(data.staticFields.size()));
    writeUleb128(out, static_cast<ca::u32>(data.instanceFields.size()));
    writeUleb128(out, static_cast<ca::u32>(data.directMethods.size()));
    writeUleb128(out, static_cast<ca::u32>(data.virtualMethods.size()));

    const auto writeFields = [&out](const std::vector<EncodedField>& fields) {
        ca::u32 previous = 0;
        bool first = true;
        for (const EncodedField& field : fields) {
            writeUleb128(out, first ? field.fieldIndex : field.fieldIndex - previous);
            writeUleb128(out, field.accessFlags);
            previous = field.fieldIndex;
            first = false;
        }
    };
    const auto writeMethods = [&out](const std::vector<EncodedMethod>& methods) {
        ca::u32 previous = 0;
        bool first = true;
        for (const EncodedMethod& method : methods) {
            writeUleb128(out, first ? method.methodIndex : method.methodIndex - previous);
            writeUleb128(out, method.accessFlags);
            writeUleb128(out, method.codeOff);
            previous = method.methodIndex;
            first = false;
        }
    };

    writeFields(data.staticFields);
    writeFields(data.instanceFields);
    writeMethods(data.directMethods);
    writeMethods(data.virtualMethods);
    return Ok(std::move(out));
}

}   // namespace dex::core
