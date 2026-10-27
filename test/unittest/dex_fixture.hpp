/// @file        dex_fixture.hpp
/// @brief       内存构造的最小合法 DEX 035 样本（测试专用）。
///
/// 样本结构：1 个类 LHello;（父类 Ljava/lang/Object;，来源文件 Hello.java），
/// 1 个实例字段 bar:I，1 个 direct 方法 foo()V（static，含 return-void 方法体），
/// 7 个字符串、4 个类型、2 个原型。所有 index 按 DEX 规范排序，checksum 与
/// signature 按真实算法计算，可作为 "Validated" 的冒烟 fixture。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"

#include "dex/core/bytes.hpp"

namespace dex_test {

/// @brief 把测试字节容器包装成 libca 视图（零拷贝）。
inline ca::core::ByteSlice asSlice(const std::vector<ca::u8>& bytes) noexcept
{
    return ca::core::ByteSlice(bytes.data(), bytes.size());
}

// 固定布局（makeHelloDex 的产物）；畸形用例按这些偏移打补丁。
constexpr ca::u32 kHeaderSize = 0x70;
constexpr ca::u32 kStringIdsTableOff = 0x70;
constexpr ca::u32 kTypeIdsTableOff = 0x8C;
constexpr ca::u32 kProtoIdsTableOff = 0x9C;
constexpr ca::u32 kFieldIdsTableOff = 0xB4;
constexpr ca::u32 kMethodIdsTableOff = 0xBC;
constexpr ca::u32 kClassDefsTableOff = 0xC4;
constexpr ca::u32 kDataOffset = 0xE4;  ///< data 区起点（字符串数据之前）

constexpr ca::u32 kHeaderChecksumField = 8;
constexpr ca::u32 kHeaderSignatureField = 12;
constexpr ca::u32 kHeaderFileSizeField = 32;
constexpr ca::u32 kHeaderSizeField = 36;
constexpr ca::u32 kHeaderEndianTagField = 40;
constexpr ca::u32 kHeaderMapOffField = 52;
constexpr ca::u32 kHeaderStringIdsOffField = 60;
constexpr ca::u32 kHeaderDataSizeField = 104;
constexpr ca::u32 kHeaderDataOffField = 108;

constexpr ca::u32 kClassDefClassDataField = kClassDefsTableOff + 24;
constexpr ca::u32 kClassDefStaticValuesField = kClassDefsTableOff + 28;

/// @brief 构造样本字节（内容确定性，同一进程内多次调用结果一致）。
std::vector<ca::u8> makeHelloDex();

/// @brief 读小端 u32（测试断言用）。
ca::u32 readU32(const std::vector<ca::u8>& bytes, ca::u32 offset);

/// @brief 写小端 u16/u32（畸形用例打补丁用）。
void patchU16(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u16 value);
void patchU32(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u32 value);

}   // namespace dex_test
