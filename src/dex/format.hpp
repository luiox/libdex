/// @file        format.hpp
/// @brief       DEX 格式层常量：reader/builder/incremental 共用的取值。
#pragma once

#include "libca/core/datatype.hpp"

namespace dex::core {

/// @brief 标准 dex header 字节数。
constexpr ca::u32 kHeaderSize = 0x70;

/// @brief 041 扩展 header 字节数（尾部追加 container 两个字段）。
constexpr ca::u32 kHeaderSizeV41 = 0x78;

/// @brief 小端文件的 endian_tag。
constexpr ca::u32 kEndianTag = 0x12345678u;

}   // namespace dex::core
