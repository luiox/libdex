/// @file        dex.hpp
/// @brief       libdex 统一入口头。
///
/// core 层：单 DexFile lazy DOM（header/map_list/五张 ID 表/class_defs eager，
/// string_data/class_data/code_item/type_list/注解族/静态初值/debug_info 按需
/// 解码）+ 未修改透传写回 + canonical 整文件重建。
/// insn 层：code_item.insns 的指令 DOM 与精确编码器；不提供方法体 AST。
/// type 层：DEX 描述符解析。
/// integrity 层：adler32 checksum 与 SHA-1 signature 的核对/重算工具。
#pragma once

#include "dex/annotation.hpp"
#include "dex/builder.hpp"
#include "dex/bytes.hpp"
#include "dex/debug_info.hpp"
#include "dex/dex_file.hpp"
#include "dex/encoded_value.hpp"
#include "dex/error.hpp"
#include "dex/insn.hpp"
#include "dex/insn_edit.hpp"
#include "dex/integrity.hpp"
#include "dex/leb128.hpp"
#include "dex/opcode.hpp"
#include "dex/reader.hpp"
#include "dex/writer.hpp"

#include "dex/descriptor.hpp"

namespace dex {

/// @brief 库版本（语义版本字符串）。
const char* get_lib_version() noexcept;

}   // namespace dex
