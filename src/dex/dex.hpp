/// @file        dex.hpp
/// @brief       libdex 统一入口头。
///
/// core 层：单 DexFile lazy DOM（header/map_list/五张 ID 表/class_defs eager，
/// string_data/class_data/code_item/type_list 按需解码）+ 未修改透传写回。
/// insn 层：code_item.insns 的指令 DOM（操作码元数据、全格式操作数、payload）。
/// type 层：DEX 描述符解析。
/// ir 层：方法体的只读 CodeDom（指令、label、try 区域）。
/// integrity 层：adler32 checksum 与 SHA-1 signature 的核对/重算工具。
#pragma once

#include "dex/core/bytes.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/integrity.hpp"
#include "dex/core/leb128.hpp"
#include "dex/core/opcode.hpp"
#include "dex/core/reader.hpp"
#include "dex/core/writer.hpp"

#include "dex/ir/code_dom.hpp"

#include "dex/type/descriptor.hpp"

namespace dex {

/// @brief 库版本（语义版本字符串，随 dev_plan 的版本节点推进）。
const char* get_lib_version() noexcept;

}   // namespace dex
