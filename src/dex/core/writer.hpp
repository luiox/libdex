/// @file        writer.hpp
/// @brief       DEX 保真写回。
///
/// 只读核阶段的写回只有一条路径：**未修改即原字节透传**。DexFile 目前没有修改
/// 入口（编辑面随编辑写回阶段落地），因此写回就是把源字节原样交回，连 header 的
/// checksum/signature 都不重算——写回不是 sanitizer，原文件校验字段本就错误时
/// 往返产物保留错误。
///
/// 后续修改路径的裁决（design.md §2.4）是「一旦修改 → 结构化全量重写单一
/// 路径」；届时在 @ref WriteError 上补齐 Unencodable/NotModeled 错误面。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief 写回一个 DexFile 为 .dex 字节。
///
/// @return 失败原因见 @ref WriteError；返回 Err 时输出字节一律作废，绝不产出
///         半成品 dex。模型借用源字节时，调用方须保证字节在写出期间有效。
Result<std::vector<ca::u8>, WriteError> writeDex(const DexFile& dex);

}   // namespace dex::core
