/// @file        error.cpp
/// @brief       错误码与解析状态的文本映射。
#include "dex/core/error.hpp"

namespace dex::core {

const char* to_string(ReadError e) noexcept
{
    switch (e) {
        case ReadError::Ok: return "ok";
        case ReadError::Truncated: return "truncated";
        case ReadError::BadMagic: return "bad_magic";
        case ReadError::UnsupportedVersion: return "unsupported_version";
        case ReadError::BadHeaderSize: return "bad_header_size";
        case ReadError::BadEndianTag: return "bad_endian_tag";
        case ReadError::BadFileSize: return "bad_file_size";
        case ReadError::BadMapList: return "bad_map_list";
        case ReadError::BadTableSpan: return "bad_table_span";
        case ReadError::BadStringData: return "bad_string_data";
        case ReadError::BadLeb128: return "bad_leb128";
        case ReadError::BadClassData: return "bad_class_data";
        case ReadError::BadCodeItem: return "bad_code_item";
        case ReadError::BadEncodedValue: return "bad_encoded_value";
        case ReadError::BadIndex: return "bad_index";
        case ReadError::BadChecksum: return "bad_checksum";
        case ReadError::BadSignature: return "bad_signature";
    }
    return "unknown";
}

const char* to_string(WriteError e) noexcept
{
    switch (e) {
        case WriteError::Ok: return "ok";
        case WriteError::MissingSource: return "missing_source";
        case WriteError::Unencodable: return "unencodable";
        case WriteError::NotModeled: return "not_modeled";
        case WriteError::SourceUnreadable: return "source_unreadable";
        case WriteError::InvalidModel: return "invalid_model";
    }
    return "unknown";
}

const char* to_string(ParseState s) noexcept
{
    switch (s) {
        case ParseState::Validated: return "validated";
        case ParseState::Recovered: return "recovered";
    }
    return "unknown";
}

}   // namespace dex::core
