/// @file        code_item.hpp
/// @brief       code_item 的结构解码与精确重编码。
///
/// 模型是目录级视图：头部计数 + 指令区 span + tries/handler 表。指令流由
/// @ref decodeInsns 解码；编码处理器表在此解析为结构化条目，共享的 handler
/// 写回时保持共享。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief encoded_catch_handler 中的一条 typed catch。
struct TypedCatch
{
    ca::u32 typeIdx = 0;
    ca::u32 address = 0;
};

/// @brief encoded_catch_handler：typed 列表 + 可选 catch-all。
struct CatchHandler
{
    std::vector<TypedCatch> typed;
    bool hasCatchAll = false;
    ca::u32 catchAllAddress = 0;
};

/// @brief try_item 与其解析后的 handler 下标。
struct TryBlock
{
    ca::u32 startAddress = 0;
    ca::u16 insnCount = 0;
    ca::u16 handlerOff = 0;   ///< 相对 encoded_catch_handler_list 起始
    ca::u32 handlerIndex = 0; ///< 指向 CodeItem::catchHandlers
};

/// @brief code_item 的目录级模型：头部 + 指令区 span + tries/handlers。
struct CodeItem
{
    ByteSpan raw;      ///< 从 code_item 起始到 tries 末尾（不含编码处理器表）
    ByteSpan insns;    ///< insns_size 个 u16 指令单元
    ByteSpan tries;    ///< tries_size 条 try_item（每条 8 字节）
    ByteSpan handlers; ///< encoded_catch_handler_list（含 handler 计数）
    ca::u32 offset = 0;
    ca::u32 debugInfoOff = 0;
    ca::u32 handlersOff = 0;  ///< 0 表示无 tries
    ca::u16 registersSize = 0;
    ca::u16 insSize = 0;
    ca::u16 outsSize = 0;
    ca::u16 triesSize = 0;
    ca::u32 insnsSize = 0;
    std::vector<TryBlock> tryBlocks;
    std::vector<CatchHandler> catchHandlers;
};

/// @brief 解析一个 code_item，不依赖 DexFile。
///
/// @param source 整个 dex 的源字节；offset 是 code_item 起始。
/// @param typeCount 仅用于对 catch 的 type 索引做 BadIndex 诊断；0 表示跳过。
/// @param diagnostics 非空时收集语义告警（try 范围/handler 地址越界、悬垂类型索引）；
///        结构性错误仍返回 Err(ReadError::BadCodeItem)。
Result<CodeItem, ReadError> parseCodeItem(ByteSlice source, ca::u32 offset,
                                          ca::u32 typeCount = 0,
                                          Diagnostics* diagnostics = nullptr);

/// @brief 精确重编码 code_item。
///
/// @param item 头部、tries 与 handler 模型；tries 的 handler_off 按
///             @ref TryBlock::handlerIndex 重新计算，共享的 handler 保持共享。
/// @param insns 已编码的指令区字节，长度必须是 `insnsSize * 2`。
/// 若 tries 非空且指令数为奇数，写回按格式补 2 字节对齐。
Result<std::vector<ca::u8>, WriteError> writeCodeItem(const CodeItem& item, ByteSlice insns);

}   // namespace dex::core
