/// @file        opcodes.cpp
/// @brief       libsmali 共享表实现。
#include "smali/opcodes.hpp"

#include <string>
#include <vector>

namespace dex::smali {

namespace {

constexpr Mnemonic kTable[] = {
    // 10x
    {0x00, "nop", core::InsnFormat::F10x},
    {0x0e, "return-void", core::InsnFormat::F10x},
    // 12x
    {0x01, "move", core::InsnFormat::F12x},
    {0x04, "move-wide", core::InsnFormat::F12x},
    {0x07, "move-object", core::InsnFormat::F12x},
    {0x21, "array-length", core::InsnFormat::F12x},
    // 11x
    {0x0a, "move-result", core::InsnFormat::F11x},
    {0x0b, "move-result-wide", core::InsnFormat::F11x},
    {0x0c, "move-result-object", core::InsnFormat::F11x},
    {0x0d, "move-exception", core::InsnFormat::F11x},
    {0x0f, "return", core::InsnFormat::F11x},
    {0x10, "return-wide", core::InsnFormat::F11x},
    {0x11, "return-object", core::InsnFormat::F11x},
    {0x1d, "monitor-enter", core::InsnFormat::F11x},
    {0x1e, "monitor-exit", core::InsnFormat::F11x},
    {0x27, "throw", core::InsnFormat::F11x},
    // 11n
    {0x12, "const/4", core::InsnFormat::F11n},
    // 21s
    {0x13, "const/16", core::InsnFormat::F21s},
    {0x16, "const-wide/16", core::InsnFormat::F21s},
    // 21h
    {0x15, "const/high16", core::InsnFormat::F21h},
    {0x19, "const-wide/high16", core::InsnFormat::F21h},
    // 21c
    {0x1a, "const-string", core::InsnFormat::F21c},
    {0x1c, "const-class", core::InsnFormat::F21c},
    {0x22, "new-instance", core::InsnFormat::F21c},
    {0x60, "sget", core::InsnFormat::F21c},
    {0x61, "sget-wide", core::InsnFormat::F21c},
    {0x62, "sget-object", core::InsnFormat::F21c},
    {0x63, "sget-boolean", core::InsnFormat::F21c},
    {0x64, "sget-byte", core::InsnFormat::F21c},
    {0x65, "sget-char", core::InsnFormat::F21c},
    {0x66, "sget-short", core::InsnFormat::F21c},
    {0x67, "sput", core::InsnFormat::F21c},
    {0x68, "sput-wide", core::InsnFormat::F21c},
    {0x69, "sput-object", core::InsnFormat::F21c},
    {0x6a, "sput-boolean", core::InsnFormat::F21c},
    {0x6b, "sput-byte", core::InsnFormat::F21c},
    {0x6c, "sput-char", core::InsnFormat::F21c},
    {0x6d, "sput-short", core::InsnFormat::F21c},
    {0xfe, "const-method-handle", core::InsnFormat::F21c},
    {0xff, "const-method-type", core::InsnFormat::F21c},
    // 31c
    {0x1b, "const-string/jumbo", core::InsnFormat::F31c},
    // 31i
    {0x14, "const", core::InsnFormat::F31i},
    {0x17, "const-wide/32", core::InsnFormat::F31i},
    // 51l
    {0x18, "const-wide", core::InsnFormat::F51l},
    // 22x
    {0x02, "move/from16", core::InsnFormat::F22x},
    {0x05, "move-wide/from16", core::InsnFormat::F22x},
    {0x08, "move-object/from16", core::InsnFormat::F22x},
    // 32x
    {0x03, "move/16", core::InsnFormat::F32x},
    {0x06, "move-wide/16", core::InsnFormat::F32x},
    {0x09, "move-object/16", core::InsnFormat::F32x},
    // 22c
    {0x1f, "check-cast", core::InsnFormat::F21c},
    {0x20, "instance-of", core::InsnFormat::F22c},
    {0x23, "new-array", core::InsnFormat::F22c},
    {0x52, "iget", core::InsnFormat::F22c},
    {0x53, "iget-wide", core::InsnFormat::F22c},
    {0x54, "iget-object", core::InsnFormat::F22c},
    {0x55, "iget-boolean", core::InsnFormat::F22c},
    {0x56, "iget-byte", core::InsnFormat::F22c},
    {0x57, "iget-char", core::InsnFormat::F22c},
    {0x58, "iget-short", core::InsnFormat::F22c},
    {0x59, "iput", core::InsnFormat::F22c},
    {0x5a, "iput-wide", core::InsnFormat::F22c},
    {0x5b, "iput-object", core::InsnFormat::F22c},
    {0x5c, "iput-boolean", core::InsnFormat::F22c},
    {0x5d, "iput-byte", core::InsnFormat::F22c},
    {0x5e, "iput-char", core::InsnFormat::F22c},
    {0x5f, "iput-short", core::InsnFormat::F22c},
    // 23x
    {0x44, "aget", core::InsnFormat::F23x},
    {0x45, "aget-wide", core::InsnFormat::F23x},
    {0x46, "aget-object", core::InsnFormat::F23x},
    {0x47, "aget-boolean", core::InsnFormat::F23x},
    {0x48, "aget-byte", core::InsnFormat::F23x},
    {0x49, "aget-char", core::InsnFormat::F23x},
    {0x4a, "aget-short", core::InsnFormat::F23x},
    {0x4b, "aput", core::InsnFormat::F23x},
    {0x4c, "aput-wide", core::InsnFormat::F23x},
    {0x4d, "aput-object", core::InsnFormat::F23x},
    {0x4e, "aput-boolean", core::InsnFormat::F23x},
    {0x4f, "aput-byte", core::InsnFormat::F23x},
    {0x50, "aput-char", core::InsnFormat::F23x},
    {0x51, "aput-short", core::InsnFormat::F23x},
    // 20t / 30t / 21t / 22t
    {0x28, "goto", core::InsnFormat::F10t},
    {0x29, "goto/16", core::InsnFormat::F20t},
    {0x2a, "goto/32", core::InsnFormat::F30t},
    {0x38, "if-eqz", core::InsnFormat::F21t},
    {0x39, "if-nez", core::InsnFormat::F21t},
    {0x3a, "if-ltz", core::InsnFormat::F21t},
    {0x3b, "if-gez", core::InsnFormat::F21t},
    {0x3c, "if-gtz", core::InsnFormat::F21t},
    {0x3d, "if-lez", core::InsnFormat::F21t},
    {0x32, "if-eq", core::InsnFormat::F22t},
    {0x33, "if-ne", core::InsnFormat::F22t},
    {0x34, "if-lt", core::InsnFormat::F22t},
    {0x35, "if-ge", core::InsnFormat::F22t},
    {0x36, "if-gt", core::InsnFormat::F22t},
    {0x37, "if-le", core::InsnFormat::F22t},
    // 31t
    {0x26, "fill-array-data", core::InsnFormat::F31t},
    {0x2b, "packed-switch", core::InsnFormat::F31t},
    {0x2c, "sparse-switch", core::InsnFormat::F31t},
    // 22b
    {0xd8, "add-int/lit8", core::InsnFormat::F22b},
    {0xd9, "rsub-int/lit8", core::InsnFormat::F22b},
    {0xda, "mul-int/lit8", core::InsnFormat::F22b},
    {0xdb, "div-int/lit8", core::InsnFormat::F22b},
    {0xdc, "rem-int/lit8", core::InsnFormat::F22b},
    {0xdd, "and-int/lit8", core::InsnFormat::F22b},
    {0xde, "or-int/lit8", core::InsnFormat::F22b},
    {0xdf, "xor-int/lit8", core::InsnFormat::F22b},
    {0xe0, "shl-int/lit8", core::InsnFormat::F22b},
    {0xe1, "shr-int/lit8", core::InsnFormat::F22b},
    {0xe2, "ushr-int/lit8", core::InsnFormat::F22b},
    // 22s
    {0xd0, "add-int/lit16", core::InsnFormat::F22s},
    {0xd1, "rsub-int", core::InsnFormat::F22s},
    {0xd2, "mul-int/lit16", core::InsnFormat::F22s},
    {0xd3, "div-int/lit16", core::InsnFormat::F22s},
    {0xd4, "rem-int/lit16", core::InsnFormat::F22s},
    {0xd5, "and-int/lit16", core::InsnFormat::F22s},
    {0xd6, "or-int/lit16", core::InsnFormat::F22s},
    {0xd7, "xor-int/lit16", core::InsnFormat::F22s},
    // 31i（比较族是 23x）/ 23x 二元
    {0x90, "add-int", core::InsnFormat::F23x},
    {0x91, "sub-int", core::InsnFormat::F23x},
    {0x92, "mul-int", core::InsnFormat::F23x},
    {0x93, "div-int", core::InsnFormat::F23x},
    {0x94, "rem-int", core::InsnFormat::F23x},
    {0x95, "and-int", core::InsnFormat::F23x},
    {0x96, "or-int", core::InsnFormat::F23x},
    {0x97, "xor-int", core::InsnFormat::F23x},
    {0x98, "shl-int", core::InsnFormat::F23x},
    {0x99, "shr-int", core::InsnFormat::F23x},
    {0x9a, "ushr-int", core::InsnFormat::F23x},
    {0x9b, "add-long", core::InsnFormat::F23x},
    {0x9c, "sub-long", core::InsnFormat::F23x},
    {0x9d, "mul-long", core::InsnFormat::F23x},
    {0x9e, "div-long", core::InsnFormat::F23x},
    {0x9f, "rem-long", core::InsnFormat::F23x},
    {0xa0, "and-long", core::InsnFormat::F23x},
    {0xa1, "or-long", core::InsnFormat::F23x},
    {0xa2, "xor-long", core::InsnFormat::F23x},
    {0xa3, "shl-long", core::InsnFormat::F23x},
    {0xa4, "shr-long", core::InsnFormat::F23x},
    {0xa5, "ushr-long", core::InsnFormat::F23x},
    {0xa6, "add-float", core::InsnFormat::F23x},
    {0xa7, "sub-float", core::InsnFormat::F23x},
    {0xa8, "mul-float", core::InsnFormat::F23x},
    {0xa9, "div-float", core::InsnFormat::F23x},
    {0xaa, "rem-float", core::InsnFormat::F23x},
    {0xab, "add-double", core::InsnFormat::F23x},
    {0xac, "sub-double", core::InsnFormat::F23x},
    {0xad, "mul-double", core::InsnFormat::F23x},
    {0xae, "div-double", core::InsnFormat::F23x},
    {0xaf, "rem-double", core::InsnFormat::F23x},
    // 比较族
    {0x2d, "cmpl-float", core::InsnFormat::F23x},
    {0x2e, "cmpg-float", core::InsnFormat::F23x},
    {0x2f, "cmpl-double", core::InsnFormat::F23x},
    {0x30, "cmpg-double", core::InsnFormat::F23x},
    {0x31, "cmp-long", core::InsnFormat::F23x},
    // 一元（12x/11x? neg-int 是 12x：vA, vB）
    {0x7b, "neg-int", core::InsnFormat::F12x},
    {0x7c, "not-int", core::InsnFormat::F12x},
    {0x7d, "neg-long", core::InsnFormat::F12x},
    {0x7e, "not-long", core::InsnFormat::F12x},
    {0x7f, "neg-float", core::InsnFormat::F12x},
    {0x80, "neg-double", core::InsnFormat::F12x},
    {0x81, "int-to-long", core::InsnFormat::F12x},
    {0x82, "int-to-float", core::InsnFormat::F12x},
    {0x83, "int-to-double", core::InsnFormat::F12x},
    {0x84, "long-to-int", core::InsnFormat::F12x},
    {0x85, "long-to-float", core::InsnFormat::F12x},
    {0x86, "long-to-double", core::InsnFormat::F12x},
    {0x87, "float-to-int", core::InsnFormat::F12x},
    {0x88, "float-to-long", core::InsnFormat::F12x},
    {0x89, "float-to-double", core::InsnFormat::F12x},
    {0x8a, "double-to-int", core::InsnFormat::F12x},
    {0x8b, "double-to-long", core::InsnFormat::F12x},
    {0x8c, "double-to-float", core::InsnFormat::F12x},
    {0x8d, "int-to-byte", core::InsnFormat::F12x},
    {0x8e, "int-to-char", core::InsnFormat::F12x},
    {0x8f, "int-to-short", core::InsnFormat::F12x},
    // 2addr
    {0xb0, "add-int/2addr", core::InsnFormat::F12x},
    {0xb1, "sub-int/2addr", core::InsnFormat::F12x},
    {0xb2, "mul-int/2addr", core::InsnFormat::F12x},
    {0xb3, "div-int/2addr", core::InsnFormat::F12x},
    {0xb4, "rem-int/2addr", core::InsnFormat::F12x},
    {0xb5, "and-int/2addr", core::InsnFormat::F12x},
    {0xb6, "or-int/2addr", core::InsnFormat::F12x},
    {0xb7, "xor-int/2addr", core::InsnFormat::F12x},
    {0xb8, "shl-int/2addr", core::InsnFormat::F12x},
    {0xb9, "shr-int/2addr", core::InsnFormat::F12x},
    {0xba, "ushr-int/2addr", core::InsnFormat::F12x},
    {0xbb, "add-long/2addr", core::InsnFormat::F12x},
    {0xbc, "sub-long/2addr", core::InsnFormat::F12x},
    {0xbd, "mul-long/2addr", core::InsnFormat::F12x},
    {0xbe, "div-long/2addr", core::InsnFormat::F12x},
    {0xbf, "rem-long/2addr", core::InsnFormat::F12x},
    {0xc0, "and-long/2addr", core::InsnFormat::F12x},
    {0xc1, "or-long/2addr", core::InsnFormat::F12x},
    {0xc2, "xor-long/2addr", core::InsnFormat::F12x},
    {0xc3, "shl-long/2addr", core::InsnFormat::F12x},
    {0xc4, "shr-long/2addr", core::InsnFormat::F12x},
    {0xc5, "ushr-long/2addr", core::InsnFormat::F12x},
    {0xc6, "add-float/2addr", core::InsnFormat::F12x},
    {0xc7, "sub-float/2addr", core::InsnFormat::F12x},
    {0xc8, "mul-float/2addr", core::InsnFormat::F12x},
    {0xc9, "div-float/2addr", core::InsnFormat::F12x},
    {0xca, "rem-float/2addr", core::InsnFormat::F12x},
    {0xcb, "add-double/2addr", core::InsnFormat::F12x},
    {0xcc, "sub-double/2addr", core::InsnFormat::F12x},
    {0xcd, "mul-double/2addr", core::InsnFormat::F12x},
    {0xce, "div-double/2addr", core::InsnFormat::F12x},
    {0xcf, "rem-double/2addr", core::InsnFormat::F12x},
    // 35c / 3rc / 45cc / 4rcc
    {0x24, "filled-new-array", core::InsnFormat::F35c},
    {0x6e, "invoke-virtual", core::InsnFormat::F35c},
    {0x6f, "invoke-super", core::InsnFormat::F35c},
    {0x70, "invoke-direct", core::InsnFormat::F35c},
    {0x71, "invoke-static", core::InsnFormat::F35c},
    {0x72, "invoke-interface", core::InsnFormat::F35c},
    {0xfc, "invoke-custom", core::InsnFormat::F35c},
    {0x25, "filled-new-array/range", core::InsnFormat::F3rc},
    {0x74, "invoke-virtual/range", core::InsnFormat::F3rc},
    {0x75, "invoke-super/range", core::InsnFormat::F3rc},
    {0x76, "invoke-direct/range", core::InsnFormat::F3rc},
    {0x77, "invoke-static/range", core::InsnFormat::F3rc},
    {0x78, "invoke-interface/range", core::InsnFormat::F3rc},
    {0xfd, "invoke-custom/range", core::InsnFormat::F3rc},
    {0xfa, "invoke-polymorphic", core::InsnFormat::F45cc},
    {0xfb, "invoke-polymorphic/range", core::InsnFormat::F4rcc},
};

constexpr ca::usize kTableSize = sizeof(kTable) / sizeof(kTable[0]);

constexpr bool cstrEq(const char* a, const char* b)
{
    while (*a != '\0' && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

// 名字与格式必须与 core 的 kOpcodes 一致；core 侧改了这里不同步，
// 编译期直接失败，不再依赖人工对表。
static_assert([]() constexpr {
    for (const auto& m : kTable) {
        const core::OpcodeInfo& info = core::opcodeInfo(m.opcode);
        if (info.format != m.format || !cstrEq(info.name, m.name)) {
            return false;
        }
    }
    return true;
}(),
             "smali kTable 与 core kOpcodes 漂移：名字或格式不一致");


struct FlagName
{
    ca::u32 bit;
    const char* name;
};

// smali 拼写；类/字段/方法共用一张表（位语义按用途解释）。
constexpr FlagName kFlags[] = {
    {0x1, "public"},          {0x2, "private"},
    {0x4, "protected"},       {0x8, "static"},
    {0x10, "final"},          {0x20, "synchronized"},
    {0x40, "volatile"},       {0x40, "bridge"},
    {0x80, "transient"},      {0x80, "varargs"},
    {0x100, "native"},        {0x200, "interface"},
    {0x400, "abstract"},      {0x800, "strictfp"},
    {0x1000, "synthetic"},    {0x2000, "annotation"},
    {0x4000, "enum"},         {0x8000, "unused"},
    {0x10000, "constructor"}, {0x20000, "declared-synchronized"},
};

}   // namespace

std::optional<Mnemonic> mnemonicOf(ca::u8 opcode) noexcept
{
    for (const Mnemonic& m : kTable) {
        if (m.opcode == opcode) {
            return m;
        }
    }
    return std::nullopt;
}

std::optional<Mnemonic> opcodeOf(std::string_view name) noexcept
{
    for (const Mnemonic& m : kTable) {
        if (name == m.name) {
            return m;
        }
    }
    return std::nullopt;
}

std::optional<ca::u32> accessFlagOf(std::string_view keyword) noexcept
{
    // 有重名位（volatile/bridge、transient/varargs）取低位拼写；高位拼写
    // （bridge/varargs）只在渲染侧由调用方按用途选择，这里统一按低位。
    for (const FlagName& f : kFlags) {
        if (keyword == f.name) {
            return f.bit;
        }
    }
    return std::nullopt;
}

std::string_view accessFlagName(ca::u32 bit) noexcept
{
    for (const FlagName& f : kFlags) {
        if (f.bit == bit) {
            return f.name;
        }
    }
    return {};
}

std::string renderAccessFlags(ca::u32 flags)
{
    std::string out;
    ca::u32 rendered = 0;
    for (const FlagName& f : kFlags) {
        // 同位多拼写（volatile/bridge、transient/varargs）只渲染首个。
        if ((flags & f.bit) != 0 && (rendered & f.bit) == 0) {
            if (!out.empty()) {
                out += ' ';
            }
            out += f.name;
            rendered |= f.bit;
        }
    }
    return out;
}

}   // namespace dex::smali
