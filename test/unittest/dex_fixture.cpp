/// @file        dex_fixture.cpp
/// @brief       最小合法 DEX 035 样本的内存构造。
#include "dex_fixture.hpp"

#include <cstring>
#include <string_view>

#include "dex/integrity.hpp"

namespace dex_test {

namespace {

constexpr ca::u32 kEndianTag = 0x12345678u;
constexpr ca::u32 kStringCount = 7;
constexpr ca::u32 kTypeCount = 4;
constexpr ca::u32 kProtoCount = 2;
constexpr ca::u32 kFieldCount = 1;
constexpr ca::u32 kMethodCount = 1;
constexpr ca::u32 kClassDefCount = 1;
constexpr ca::u32 kMapItemCount = 16;

// string_ids 按 UTF-16 内容升序排列（DEX 规范约束）。
constexpr std::string_view kStrings[kStringCount] = {
    "Hello.java",           // 0
    "I",                    // 1
    "LHello;",              // 2
    "Ljava/lang/Object;",   // 3
    "V",                    // 4
    "bar",                  // 5
    "foo",                  // 6
};

constexpr ca::u32 align4(ca::u32 value) noexcept
{
    return (value + 3u) & ~3u;
}

void putU16(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u16 value)
{
    bytes[offset] = static_cast<ca::u8>(value);
    bytes[offset + 1] = static_cast<ca::u8>(value >> 8);
}

void appendU16(std::vector<ca::u8>& out, ca::u16 value)
{
    out.push_back(static_cast<ca::u8>(value));
    out.push_back(static_cast<ca::u8>(value >> 8));
}

void appendU32(std::vector<ca::u8>& out, ca::u32 value)
{
    out.push_back(static_cast<ca::u8>(value));
    out.push_back(static_cast<ca::u8>(value >> 8));
    out.push_back(static_cast<ca::u8>(value >> 16));
    out.push_back(static_cast<ca::u8>(value >> 24));
}

void appendUleb128(std::vector<ca::u8>& out, ca::u32 value)
{
    do {
        ca::u8 byte = static_cast<ca::u8>(value & 0x7fu);
        value >>= 7;
        if (value != 0) {
            byte = static_cast<ca::u8>(byte | 0x80u);
        }
        out.push_back(byte);
    } while (value != 0);
}

void putU32(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u32 value)
{
    bytes[offset] = static_cast<ca::u8>(value);
    bytes[offset + 1] = static_cast<ca::u8>(value >> 8);
    bytes[offset + 2] = static_cast<ca::u8>(value >> 16);
    bytes[offset + 3] = static_cast<ca::u8>(value >> 24);
}

void appendMapItem(std::vector<ca::u8>& out, ca::u16 type, ca::u32 size, ca::u32 offset)
{
    appendU16(out, type);
    appendU16(out, 0);
    appendU32(out, size);
    appendU32(out, offset);
}

}   // namespace

std::vector<ca::u8> makeHelloDex()
{
    // 表区布局：[header][string_ids][type_ids][proto_ids][field_ids][method_ids][class_defs]
    constexpr ca::u32 dataOff = align4(kClassDefsTableOff + kClassDefCount * 32u);  // 0xE4

    std::vector<ca::u8> data;
    ca::u32 stringDataOffsets[kStringCount] = {};

    for (ca::u32 i = 0; i < kStringCount; ++i) {
        stringDataOffsets[i] = dataOff + static_cast<ca::u32>(data.size());
        const std::string_view text = kStrings[i];
        appendUleb128(data, static_cast<ca::u32>(text.size()));
        for (char ch : text) {
            data.push_back(static_cast<ca::u8>(ch));
        }
        data.push_back(0);
    }

    // code_item 需要 4 字节对齐；放在字符串数据之后。
    const ca::u32 codeOff = align4(dataOff + static_cast<ca::u32>(data.size()));
    data.resize(codeOff - dataOff, 0);
    appendU16(data, 0);          // registers_size
    appendU16(data, 0);          // ins_size
    appendU16(data, 0);          // outs_size
    appendU16(data, 0);          // tries_size
    appendU32(data, 0);          // debug_info_off（稍后回填）
    appendU32(data, 1);          // insns_size
    appendU16(data, 0x000eu);    // return-void

    const ca::u32 debugInfoOff = dataOff + static_cast<ca::u32>(data.size());
    appendUleb128(data, 0);      // line_start
    appendUleb128(data, 0);      // parameters_size
    data.push_back(0);           // END_SEQUENCE

    const ca::u32 staticValuesOff = dataOff + static_cast<ca::u32>(data.size());
    appendUleb128(data, 0);      // encoded_array_item：空数组

    const ca::u32 methodHandleOff = align4(dataOff + static_cast<ca::u32>(data.size()));
    data.resize(methodHandleOff - dataOff, 0);
    appendU16(data, 4);          // method_handle_type：invoke-static
    appendU16(data, 0xBEEF);     // unused（保真保留）
    appendU16(data, 0);          // field_or_method_id：method 0
    appendU16(data, 0xCAFE);     // unused（保真保留）

    const ca::u32 callSiteOff = dataOff + static_cast<ca::u32>(data.size());
    appendU32(data, staticValuesOff);  // call_site_off → 空 encoded_array

    const ca::u32 classDataOff = dataOff + static_cast<ca::u32>(data.size());
    appendUleb128(data, 0);      // static_fields_size
    appendUleb128(data, 1);      // instance_fields_size
    appendUleb128(data, 1);      // direct_methods_size
    appendUleb128(data, 0);      // virtual_methods_size
    appendUleb128(data, 0);      // field_idx_diff：field 0
    appendUleb128(data, 0x2);    // access_flags：private
    appendUleb128(data, 0);      // method_idx_diff：method 0
    appendUleb128(data, 0x9);    // access_flags：public static
    appendUleb128(data, codeOff);

    // 未建模 section：map 类型 0x7F00（未定义类型，避免与真实 hiddenapi 语义混淆），内容按原字节透传。
    const ca::u32 unknownOff = dataOff + static_cast<ca::u32>(data.size());
    data.push_back(0xDE);
    data.push_back(0xAD);
    data.push_back(0xBE);
    data.push_back(0xEF);

    const ca::u32 mapOff = align4(dataOff + static_cast<ca::u32>(data.size()));
    data.resize(mapOff - dataOff, 0);
    appendU32(data, kMapItemCount);
    appendMapItem(data, 0x0000, 1, 0);                    // header_item
    appendMapItem(data, 0x0001, kStringCount, kStringIdsTableOff);
    appendMapItem(data, 0x0002, kTypeCount, kTypeIdsTableOff);
    appendMapItem(data, 0x0003, kProtoCount, kProtoIdsTableOff);
    appendMapItem(data, 0x0004, kFieldCount, kFieldIdsTableOff);
    appendMapItem(data, 0x0005, kMethodCount, kMethodIdsTableOff);
    appendMapItem(data, 0x0006, kClassDefCount, kClassDefsTableOff);
    appendMapItem(data, 0x2002, kStringCount, dataOff);   // string_data_item
    appendMapItem(data, 0x2001, 1, codeOff);              // code_item
    appendMapItem(data, 0x2003, 1, debugInfoOff);         // debug_info_item
    appendMapItem(data, 0x2005, 1, staticValuesOff);      // encoded_array_item
    appendMapItem(data, 0x0008, 1, methodHandleOff);      // method_handle_item
    appendMapItem(data, 0x0007, 1, callSiteOff);          // call_site_id_item
    appendMapItem(data, 0x2000, 1, classDataOff);         // class_data_item
    appendMapItem(data, 0x7F00, 1, unknownOff);         // 未建模 section
    appendMapItem(data, 0x1000, 1, mapOff);               // map_list

    const ca::u32 fileSize = dataOff + static_cast<ca::u32>(data.size());
    std::vector<ca::u8> file(fileSize, 0);

    // header
    const char magic[8] = {'d', 'e', 'x', '\n', '0', '3', '5', 0};
    std::memcpy(file.data(), magic, sizeof(magic));
    putU32(file, kHeaderFileSizeField, fileSize);
    putU32(file, kHeaderSizeField, kHeaderSize);
    putU32(file, kHeaderEndianTagField, kEndianTag);
    putU32(file, kHeaderMapOffField, mapOff);
    putU32(file, 56, kStringCount);
    putU32(file, kHeaderStringIdsOffField, kStringIdsTableOff);
    putU32(file, 64, kTypeCount);
    putU32(file, 68, kTypeIdsTableOff);
    putU32(file, 72, kProtoCount);
    putU32(file, 76, kProtoIdsTableOff);
    putU32(file, 80, kFieldCount);
    putU32(file, 84, kFieldIdsTableOff);
    putU32(file, 88, kMethodCount);
    putU32(file, 92, kMethodIdsTableOff);
    putU32(file, 96, kClassDefCount);
    putU32(file, 100, kClassDefsTableOff);
    putU32(file, kHeaderDataSizeField, fileSize - dataOff);
    putU32(file, kHeaderDataOffField, dataOff);

    // string_ids
    for (ca::u32 i = 0; i < kStringCount; ++i) {
        putU32(file, kStringIdsTableOff + i * 4u, stringDataOffsets[i]);
    }

    // type_ids：I / LHello; / Ljava/lang/Object; / V（按 descriptor string 索引升序）
    const ca::u32 typeDescriptors[kTypeCount] = {1, 2, 3, 4};
    for (ca::u32 i = 0; i < kTypeCount; ++i) {
        putU32(file, kTypeIdsTableOff + i * 4u, typeDescriptors[i]);
    }

    // proto_ids：()I 在前（返回类型索引 0），()V 在后（返回类型索引 3）
    putU32(file, kProtoIdsTableOff + 0, 1);   // shorty "I"
    putU32(file, kProtoIdsTableOff + 4, 0);   // return type I
    putU32(file, kProtoIdsTableOff + 8, 0);   // parameters_off
    putU32(file, kProtoIdsTableOff + 12, 4);  // shorty "V"
    putU32(file, kProtoIdsTableOff + 16, 3);  // return type V
    putU32(file, kProtoIdsTableOff + 20, 0);  // parameters_off

    // field_ids：LHello;->bar:I
    putU16(file, kFieldIdsTableOff + 0, 1);  // class_idx = LHello;
    putU16(file, kFieldIdsTableOff + 2, 0);  // type_idx = I
    putU32(file, kFieldIdsTableOff + 4, 5);  // name_idx = "bar"

    // method_ids：LHello;->foo()V
    putU16(file, kMethodIdsTableOff + 0, 1);  // class_idx = LHello;
    putU16(file, kMethodIdsTableOff + 2, 1);  // proto_idx = ()V
    putU32(file, kMethodIdsTableOff + 4, 6);  // name_idx = "foo"

    // class_defs：LHello; extends Ljava/lang/Object;
    putU32(file, kClassDefsTableOff + 0, 1);                 // class_idx
    putU32(file, kClassDefsTableOff + 4, 0x1);               // public
    putU32(file, kClassDefsTableOff + 8, 2);                 // superclass_idx = Object
    putU32(file, kClassDefsTableOff + 12, 0);                // interfaces_off
    putU32(file, kClassDefsTableOff + 16, 0);                // source_file_idx = Hello.java
    putU32(file, kClassDefsTableOff + 20, 0);                // annotations_off
    putU32(file, kClassDefsTableOff + 24, classDataOff);     // class_data_off
    putU32(file, kClassDefsTableOff + 28, staticValuesOff);  // static_values_off

    std::memcpy(file.data() + dataOff, data.data(), data.size());
    putU32(file, codeOff + 8, debugInfoOff);  // code_item.debug_info_off

    // 先写 signature（覆盖 offset 32 起），再算 checksum（覆盖 offset 12 起，
    // 因此必须包含已写入的 signature 字段）。
    const dex::core::ByteSlice all{file.data(), file.size()};
    const std::array<ca::u8, 20> signature =
        dex::core::sha1Digest(dex::core::subOrEmpty(all, 32, file.size() - 32));
    std::memcpy(file.data() + kHeaderSignatureField, signature.data(), signature.size());
    putU32(file, kHeaderChecksumField,
           dex::core::adler32(dex::core::subOrEmpty(all, 12, file.size() - 12)));

    return file;
}

ca::u32 readU32(const std::vector<ca::u8>& bytes, ca::u32 offset)
{
    return static_cast<ca::u32>(bytes[offset]) |
           (static_cast<ca::u32>(bytes[offset + 1]) << 8) |
           (static_cast<ca::u32>(bytes[offset + 2]) << 16) |
           (static_cast<ca::u32>(bytes[offset + 3]) << 24);
}

void patchU16(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u16 value)
{
    bytes[offset] = static_cast<ca::u8>(value);
    bytes[offset + 1] = static_cast<ca::u8>(value >> 8);
}

void patchU32(std::vector<ca::u8>& bytes, ca::u32 offset, ca::u32 value)
{
    putU32(bytes, offset, value);
}

}   // namespace dex_test
