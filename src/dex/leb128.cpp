/// @file        leb128.cpp
/// @brief       ULEB128 读取（32 位域）。
#include "dex/leb128.hpp"

namespace dex::core {

Result<ca::u32, ReadError> readUleb128(Reader& cur) noexcept
{
    ca::u32 value = 0;
    ca::u32 shift = 0;

    for (ca::u32 i = 0; i < 5; ++i) {
        const Result<ca::u8, ReadError> rb = cur.u8();
        if (rb.is_err()) {
            return Err(rb.unwrap_err());
        }
        const ca::u8 byte = rb.unwrap();

        // 第 5 字节只承载低 4 位；更高位是溢出，不是合法编码。
        if (i == 4 && (byte & 0x80u) != 0) {
            return Err(ReadError::BadLeb128);
        }
        if (i == 4 && byte > 0x0fu) {
            return Err(ReadError::BadLeb128);
        }

        value |= static_cast<ca::u32>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0) {
            return Ok(value);
        }
        shift += 7;
    }

    return Err(ReadError::BadLeb128);
}

Result<ca::i32, ReadError> readSleb128(Reader& cur) noexcept
{
    ca::u32 value = 0;
    ca::u32 shift = 0;

    for (ca::u32 i = 0; i < 5; ++i) {
        const Result<ca::u8, ReadError> rb = cur.u8();
        if (rb.is_err()) {
            return Err(rb.unwrap_err());
        }
        const ca::u8 byte = rb.unwrap();

        if (i == 4 && (byte & 0x80u) != 0) {
            return Err(ReadError::BadLeb128);
        }

        value |= static_cast<ca::u32>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0) {
            // 符号位在第 shift+7 位；未填满 32 位时显式补齐高位。
            if (shift + 7 < 32 && (byte & 0x40u) != 0) {
                value |= ~ca::u32{0} << (shift + 7);
            }
            return Ok(static_cast<ca::i32>(value));
        }
        shift += 7;
    }

    return Err(ReadError::BadLeb128);
}

void writeUleb128(std::vector<ca::u8>& out, ca::u32 value)
{
    do {
        ca::u8 byte = static_cast<ca::u8>(value & 0x7Fu);
        value >>= 7;
        if (value != 0) {
            byte = static_cast<ca::u8>(byte | 0x80u);
        }
        out.push_back(byte);
    } while (value != 0);
}

void writeSleb128(std::vector<ca::u8>& out, ca::i32 value)
{
    bool more = true;
    while (more) {
        ca::u8 byte = static_cast<ca::u8>(value & 0x7F);
        value >>= 7;  // 算术右移
        const bool signSet = (byte & 0x40u) != 0;
        more = !((value == 0 && !signSet) || (value == -1 && signSet));
        if (more) {
            byte = static_cast<ca::u8>(byte | 0x80u);
        }
        out.push_back(byte);
    }
}

}   // namespace dex::core
