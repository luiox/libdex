/// @file        reader.hpp
/// @brief       DEX 骨架解析入口（eager 骨架 + lazy 数据）。
///
/// @ref readDex 只解析「必须解析才能定位结构」的部分：header、map_list、五张
/// ID 表的定长条目、class_defs。string_data / class_data / code_item / type_list
/// 一律只记目录并按需解码，因此解析代价与类体规模无关。
///
/// 失败的语义是「无法确定后续结构边界」，不是「输入不合法」：畸形输入的
/// 降级结果（校验和不符、悬垂索引、map 计数不符）落在
/// @ref ParseState::Recovered 与 @ref Diagnostics 里，而不是异常或半截模型。
#pragma once

#include <memory>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/core/bytes.hpp"
#include "dex/core/dex_file.hpp"
#include "dex/core/error.hpp"

namespace dex::core {

/// @brief 读取选项。
struct ReadOptions
{
    /// @brief 保留源字节副本——lazy 解码与保真写回的共同前提。
    ///
    /// 开启（默认）时字节被复制进模型，解析产出的一切视图（字符串、class_data、
    /// code_item span）都指向模型内部，与调用方 buffer 生命周期解耦。
    ///
    /// 关掉它可省一份与输入等大的内存，代价是：所有字节视图改为借用入参
    /// buffer，调用方必须保证它在模型存活期内有效；写回仍可透传（同样要求
    /// buffer 存活）。
    bool preserveSourceBytes = true;

    /// @brief 核对 header 的 adler32 checksum 与 SHA-1 signature。
    ///
    /// 核对失败只记诊断（模型进入 Recovered），不拒绝读取——分析对象常常
    /// 是被工具改过头部字段的产物。
    bool verifyIntegrity = true;

    /// @brief 版本号上限；已知但超过上限的版本只降级记录，不拒绝读取。
    ca::u16 maxSupportedVersion = 41;
};

/// @brief 解析一个 .dex 文件的骨架。
///
/// @param bytes 输入字节；在 @ref ReadOptions::preserveSourceBytes 下会被复制进
///              模型，调用方可在返回后立即释放。
/// @return 成功时返回单 DexFile 唯一所有者；结构不可定位时返回 Err。
Result<std::unique_ptr<DexFile>, ReadError> readDex(ByteSlice bytes,
                                                    const ReadOptions& opt = ReadOptions{});

}   // namespace dex::core
