/// @file        writer.hpp
/// @brief       DEX 未修改透传写回。
///
/// @ref writeDex 是保真透传：把源字节原样交回，连 header 的 checksum/signature
/// 都不重算——写回不是 sanitizer，原文件校验字段本就错误时往返产物保留错误。
/// 库不检测模型是否被修改，也不自动选择写回路径：透传原样交回源字节，
/// 改动后的文件由调用方显式走 @ref buildDex（canonical 重排 + 校验字段重算）。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/dex_file.hpp"
#include "dex/error.hpp"

namespace dex::core {

/// @brief 写回一个 DexFile 为 .dex 字节。
///
/// @return 失败原因见 @ref WriteError；返回 Err 时输出字节一律作废，绝不产出
///         半成品 dex。模型借用源字节时，调用方须保证字节在写出期间有效。
Result<std::vector<ca::u8>, WriteError> writeDex(const DexFile& dex);

}   // namespace dex::core
