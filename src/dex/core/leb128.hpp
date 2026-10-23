/// @file        leb128.hpp
/// @brief       DEX 的 ULEB128 读取面。
///
/// LEB128 是 DEX 与 JVM 字节核的第二处编码差异：string_data 尺寸、class_data
/// 计数/差分、code_item 的编码处理器表都用变长整数。读取面在 libdex 自持：
/// libca 的 `get_var_u32` 只接受最小编码，而 DEX 读取面需要按 ART 的宽容度
/// 接受非最小编码，避免混淆产物被误拒。写入端用 libca 的 `put_var_u32`。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief 读取一个 ULEB128（32 位域）。
///
/// 最多 5 字节；第 5 字节仍带继续位、或有效位超过 32 位时返回
/// Err(ReadError::BadLeb128)。字节不足返回 Err(ReadError::Truncated)。
Result<ca::u32, ReadError> readUleb128(Reader& cur) noexcept;

/// @brief 读取一个 SLEB128（32 位有符号域）。
///
/// 用于 encoded_catch_handler 的 typed 计数。与 ULEB 同样接受冗余编码；
/// 第 5 字节仍带继续位返回 Err(ReadError::BadLeb128)，字节不足返回
/// Err(ReadError::Truncated)。
Result<ca::i32, ReadError> readSleb128(Reader& cur) noexcept;

/// @brief 写出最小编码的 ULEB128（32 位域）。
void writeUleb128(std::vector<ca::u8>& out, ca::u32 value);

/// @brief 写出最小编码的 SLEB128（32 位域）。
void writeSleb128(std::vector<ca::u8>& out, ca::i32 value);

}   // namespace dex::core
