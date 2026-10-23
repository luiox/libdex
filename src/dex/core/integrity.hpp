/// @file        integrity.hpp
/// @brief       DEX 头校验字段：adler32 checksum 与 SHA-1 signature。
///
/// DEX 的两段覆盖区：
///   - checksum 覆盖 checksum 字段之后的全部字节（offset 12 起）；
///   - signature 覆盖 signature 字段之后的全部字节（offset 32 起）。
///
/// 读取路径只**核对**、不重算写回；未修改文件的写回原样透传，连错误的校验
/// 字段也保留（写回不是 sanitizer）。修改后的重算属于编辑写回阶段。
#pragma once

#include <array>

#include "libca/core/datatype.hpp"

#include "dex/core/bytes.hpp"

namespace dex::core {

/// @brief 计算 adler32（DEX checksum 算法）。
ca::u32 adler32(ByteSlice data) noexcept;

/// @brief 计算 SHA-1 摘要（DEX signature 算法）。
std::array<ca::u8, 20> sha1Digest(ByteSlice data);

/// @brief 头部校验结果。
struct Integrity
{
    bool checksumOk = false;
    bool signatureOk = false;

    bool ok() const noexcept { return checksumOk && signatureOk; }
};

/// @brief 核对头部声明的 checksum/signature 与实际字节是否一致。
///
/// 输入是完整文件字节；两个覆盖区不足时对应项为 false。核对不修改任何字节。
Integrity verifyIntegrity(ByteSlice source,
                          ca::u32 expectedChecksum,
                          const std::array<ca::u8, 20>& expectedSignature);

}   // namespace dex::core
