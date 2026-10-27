// 041 标准 dex 写回：canonical 重建解除拒绝，container 字段按独立文件
// 约定重置为 (file_size, 0)，header_size 扩到 0x78。增量路径对 041 保持
// NotModeled（实物语料未到，见 corpus_040_041_notes）。
#include <gtest/gtest.h>

#include "dex/core/builder.hpp"
#include "dex/core/reader.hpp"
#include "dex_fixture.hpp"
#include "smali/assemble.hpp"

namespace {

dex::core::BuildOptions kNoEdits{};

}   // namespace

TEST(Dex041, CanonicalWriteResetsContainerFields)
{
    auto file = dex::core::DexFile::createEmpty(41);
    ASSERT_NE(file, nullptr);
    dex::smali::SmaliAssembler assembler(*file);
    const char* kSrc =
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static hello()Ljava/lang/String;\n"
        "    .registers 1\n"
        "    const-string v0 \"hi\"\n"
        "    return-object v0\n"
        ".end method\n";
    auto assembled = assembler.assembleClass(kSrc);
    ASSERT_TRUE(assembled.is_ok());
    auto options = assembler.options();
    options.keepUnknownSections = false;

    auto built = dex::core::buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << dex::core::to_string(built.unwrap_err());
    const std::vector<ca::u8>& bytes = built.unwrap();
    ASSERT_GE(bytes.size(), 0x78u);

    // magic 与 header_size。
    EXPECT_EQ(bytes[3], static_cast<ca::u8>('\n'));
    EXPECT_EQ(bytes[4], static_cast<ca::u8>('0'));
    EXPECT_EQ(bytes[5], static_cast<ca::u8>('4'));
    EXPECT_EQ(bytes[6], static_cast<ca::u8>('1'));
    const auto readU32 = [&bytes](ca::u32 off) {
        return static_cast<ca::u32>(bytes[off]) |
               (static_cast<ca::u32>(bytes[off + 1]) << 8) |
               (static_cast<ca::u32>(bytes[off + 2]) << 16) |
               (static_cast<ca::u32>(bytes[off + 3]) << 24);
    };
    EXPECT_EQ(readU32(36), 0x78u);
    // 独立文件约定：container_size == file_size，header_offset == 0。
    EXPECT_EQ(readU32(112), readU32(32));
    EXPECT_EQ(readU32(116), 0u);

    auto reparsed = dex::core::readDex(dex_test::asSlice(bytes));
    ASSERT_TRUE(reparsed.is_ok()) << dex::core::to_string(reparsed.unwrap_err());
    std::unique_ptr<dex::core::DexFile> out = std::move(reparsed).unwrap();
    EXPECT_EQ(out->header.version, 41u);
    EXPECT_EQ(out->header.containerSize, bytes.size());
    EXPECT_EQ(out->header.headerOffset, 0u);
    EXPECT_EQ(out->classCount(), 1u);
}

TEST(Dex041, IncrementalStaysNotModeled)
{
    auto file = dex::core::DexFile::createEmpty(41);
    ASSERT_NE(file, nullptr);
    dex::smali::SmaliAssembler assembler(*file);
    const char* kSrc =
        ".class public LUse;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static hello()V\n"
        "    .registers 1\n"
        "    return-void\n"
        ".end method\n";
    auto assembled = assembler.assembleClass(kSrc);
    ASSERT_TRUE(assembled.is_ok());
    auto options = assembler.options();

    dex::core::BuildOptions incremental;
    incremental.incremental = true;
    // 无源字节：MissingSource 先于版本闸门；给一份源再验证版本闸门。
    auto noSource = dex::core::buildDex(*file, incremental);
    EXPECT_TRUE(noSource.is_err());

    auto built = dex::core::buildDex(*file, options);
    ASSERT_TRUE(built.is_ok());
    auto reparsed = dex::core::readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<dex::core::DexFile> out = std::move(reparsed).unwrap();
    auto gated = dex::core::buildDex(*out, incremental);
    ASSERT_TRUE(gated.is_err());
    EXPECT_EQ(gated.unwrap_err(), dex::core::WriteError::NotModeled);
}
