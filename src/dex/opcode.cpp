/// @file        opcode.cpp
/// @brief       操作码元数据表与格式宽度。
#include "dex/opcode.hpp"

namespace dex::core {

namespace {

constexpr OpcodeInfo kOpcodes[256] = {
    // 0x00–0x0f：nop / move / move-result / return
    OpcodeInfo{"nop", InsnFormat::F10x, IndexKind::None},
    OpcodeInfo{"move", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"move/from16", InsnFormat::F22x, IndexKind::None},
    OpcodeInfo{"move/16", InsnFormat::F32x, IndexKind::None},
    OpcodeInfo{"move-wide", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"move-wide/from16", InsnFormat::F22x, IndexKind::None},
    OpcodeInfo{"move-wide/16", InsnFormat::F32x, IndexKind::None},
    OpcodeInfo{"move-object", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"move-object/from16", InsnFormat::F22x, IndexKind::None},
    OpcodeInfo{"move-object/16", InsnFormat::F32x, IndexKind::None},
    OpcodeInfo{"move-result", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"move-result-wide", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"move-result-object", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"move-exception", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"return-void", InsnFormat::F10x, IndexKind::None},
    OpcodeInfo{"return", InsnFormat::F11x, IndexKind::None},

    // 0x10–0x1f：return / const / const-string / monitor / check-cast
    OpcodeInfo{"return-wide", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"return-object", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"const/4", InsnFormat::F11n, IndexKind::None},
    OpcodeInfo{"const/16", InsnFormat::F21s, IndexKind::None},
    OpcodeInfo{"const", InsnFormat::F31i, IndexKind::None},
    OpcodeInfo{"const/high16", InsnFormat::F21h, IndexKind::None},
    OpcodeInfo{"const-wide/16", InsnFormat::F21s, IndexKind::None},
    OpcodeInfo{"const-wide/32", InsnFormat::F31i, IndexKind::None},
    OpcodeInfo{"const-wide", InsnFormat::F51l, IndexKind::None},
    OpcodeInfo{"const-wide/high16", InsnFormat::F21h, IndexKind::None},
    OpcodeInfo{"const-string", InsnFormat::F21c, IndexKind::String},
    OpcodeInfo{"const-string/jumbo", InsnFormat::F31c, IndexKind::String},
    OpcodeInfo{"const-class", InsnFormat::F21c, IndexKind::Type},
    OpcodeInfo{"monitor-enter", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"monitor-exit", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"check-cast", InsnFormat::F21c, IndexKind::Type},

    // 0x20–0x2f：instance/array/throw/分支/比较
    OpcodeInfo{"instance-of", InsnFormat::F22c, IndexKind::Type},
    OpcodeInfo{"array-length", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"new-instance", InsnFormat::F21c, IndexKind::Type},
    OpcodeInfo{"new-array", InsnFormat::F22c, IndexKind::Type},
    OpcodeInfo{"filled-new-array", InsnFormat::F35c, IndexKind::Type},
    OpcodeInfo{"filled-new-array/range", InsnFormat::F3rc, IndexKind::Type},
    OpcodeInfo{"fill-array-data", InsnFormat::F31t, IndexKind::None},
    OpcodeInfo{"throw", InsnFormat::F11x, IndexKind::None},
    OpcodeInfo{"goto", InsnFormat::F10t, IndexKind::None},
    OpcodeInfo{"goto/16", InsnFormat::F20t, IndexKind::None},
    OpcodeInfo{"goto/32", InsnFormat::F30t, IndexKind::None},
    OpcodeInfo{"packed-switch", InsnFormat::F31t, IndexKind::None},
    OpcodeInfo{"sparse-switch", InsnFormat::F31t, IndexKind::None},
    OpcodeInfo{"cmpl-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"cmpg-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"cmpl-double", InsnFormat::F23x, IndexKind::None},

    // 0x30–0x3f：比较 / if / 未定义
    OpcodeInfo{"cmpg-double", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"cmp-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"if-eq", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-ne", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-lt", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-ge", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-gt", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-le", InsnFormat::F22t, IndexKind::None},
    OpcodeInfo{"if-eqz", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{"if-nez", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{"if-ltz", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{"if-gez", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{"if-gtz", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{"if-lez", InsnFormat::F21t, IndexKind::None},
    OpcodeInfo{},
    OpcodeInfo{},

    // 0x40–0x4f：数组读写
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{"aget", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-wide", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-object", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-boolean", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-byte", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-char", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aget-short", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput-wide", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput-object", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput-boolean", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput-byte", InsnFormat::F23x, IndexKind::None},

    // 0x50–0x5f：数组读写 / 实例字段
    OpcodeInfo{"aput-char", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"aput-short", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"iget", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-wide", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-object", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-boolean", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-byte", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-char", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iget-short", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-wide", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-object", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-boolean", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-byte", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-char", InsnFormat::F22c, IndexKind::Field},
    OpcodeInfo{"iput-short", InsnFormat::F22c, IndexKind::Field},

    // 0x60–0x6f：静态字段 / invoke
    OpcodeInfo{"sget", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-wide", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-object", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-boolean", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-byte", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-char", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sget-short", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-wide", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-object", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-boolean", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-byte", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-char", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"sput-short", InsnFormat::F21c, IndexKind::Field},
    OpcodeInfo{"invoke-virtual", InsnFormat::F35c, IndexKind::Method},
    OpcodeInfo{"invoke-super", InsnFormat::F35c, IndexKind::Method},

    // 0x70–0x7f：invoke / 一元运算
    OpcodeInfo{"invoke-direct", InsnFormat::F35c, IndexKind::Method},
    OpcodeInfo{"invoke-static", InsnFormat::F35c, IndexKind::Method},
    OpcodeInfo{"invoke-interface", InsnFormat::F35c, IndexKind::Method},
    OpcodeInfo{},
    OpcodeInfo{"invoke-virtual/range", InsnFormat::F3rc, IndexKind::Method},
    OpcodeInfo{"invoke-super/range", InsnFormat::F3rc, IndexKind::Method},
    OpcodeInfo{"invoke-direct/range", InsnFormat::F3rc, IndexKind::Method},
    OpcodeInfo{"invoke-static/range", InsnFormat::F3rc, IndexKind::Method},
    OpcodeInfo{"invoke-interface/range", InsnFormat::F3rc, IndexKind::Method},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{"neg-int", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"not-int", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"neg-long", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"not-long", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"neg-float", InsnFormat::F12x, IndexKind::None},

    // 0x80–0x8f：类型转换
    OpcodeInfo{"neg-double", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-long", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-float", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-double", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"long-to-int", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"long-to-float", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"long-to-double", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"float-to-int", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"float-to-long", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"float-to-double", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"double-to-int", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"double-to-long", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"double-to-float", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-byte", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-char", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"int-to-short", InsnFormat::F12x, IndexKind::None},

    // 0x90–0x9f：二元运算
    OpcodeInfo{"add-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"sub-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"mul-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"div-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"rem-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"and-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"or-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"xor-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"shl-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"shr-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"ushr-int", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"add-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"sub-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"mul-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"div-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"rem-long", InsnFormat::F23x, IndexKind::None},

    // 0xa0–0xaf：二元运算
    OpcodeInfo{"and-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"or-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"xor-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"shl-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"shr-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"ushr-long", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"add-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"sub-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"mul-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"div-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"rem-float", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"add-double", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"sub-double", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"mul-double", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"div-double", InsnFormat::F23x, IndexKind::None},
    OpcodeInfo{"rem-double", InsnFormat::F23x, IndexKind::None},

    // 0xb0–0xbf：/2addr 运算
    OpcodeInfo{"add-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"sub-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"mul-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"div-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"rem-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"and-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"or-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"xor-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"shl-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"shr-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"ushr-int/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"add-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"sub-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"mul-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"div-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"rem-long/2addr", InsnFormat::F12x, IndexKind::None},

    // 0xc0–0xcf：/2addr 运算
    OpcodeInfo{"and-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"or-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"xor-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"shl-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"shr-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"ushr-long/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"add-float/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"sub-float/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"mul-float/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"div-float/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"rem-float/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"add-double/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"sub-double/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"mul-double/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"div-double/2addr", InsnFormat::F12x, IndexKind::None},
    OpcodeInfo{"rem-double/2addr", InsnFormat::F12x, IndexKind::None},

    // 0xd0–0xdf：lit16 / lit8
    OpcodeInfo{"add-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"rsub-int", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"mul-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"div-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"rem-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"and-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"or-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"xor-int/lit16", InsnFormat::F22s, IndexKind::None},
    OpcodeInfo{"add-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"rsub-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"mul-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"div-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"rem-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"and-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"or-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"xor-int/lit8", InsnFormat::F22b, IndexKind::None},

    // 0xe0–0xef：lit8 / 未定义
    OpcodeInfo{"shl-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"shr-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{"ushr-int/lit8", InsnFormat::F22b, IndexKind::None},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},

    // 0xf0–0xff：未定义 / invoke-polymorphic / invoke-custom / method handle
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{},
    OpcodeInfo{"invoke-polymorphic", InsnFormat::F45cc, IndexKind::Method},
    OpcodeInfo{"invoke-polymorphic/range", InsnFormat::F4rcc, IndexKind::Method},
    OpcodeInfo{"invoke-custom", InsnFormat::F35c, IndexKind::CallSite},
    OpcodeInfo{"invoke-custom/range", InsnFormat::F3rc, IndexKind::CallSite},
    OpcodeInfo{"const-method-handle", InsnFormat::F21c, IndexKind::MethodHandle},
    OpcodeInfo{"const-method-type", InsnFormat::F21c, IndexKind::Proto},
};

static_assert(sizeof(kOpcodes) / sizeof(kOpcodes[0]) == 256, "opcode table must cover 0x00-0xff");

}   // namespace

ca::u32 insnWidth(InsnFormat format) noexcept
{
    switch (format) {
    case InsnFormat::F10x:
    case InsnFormat::F12x:
    case InsnFormat::F11n:
    case InsnFormat::F11x:
    case InsnFormat::F10t:
        return 1;
    case InsnFormat::F20t:
    case InsnFormat::F22x:
    case InsnFormat::F21t:
    case InsnFormat::F21s:
    case InsnFormat::F21h:
    case InsnFormat::F21c:
    case InsnFormat::F23x:
    case InsnFormat::F22b:
    case InsnFormat::F22t:
    case InsnFormat::F22s:
    case InsnFormat::F22c:
        return 2;
    case InsnFormat::F30t:
    case InsnFormat::F32x:
    case InsnFormat::F31i:
    case InsnFormat::F31t:
    case InsnFormat::F31c:
    case InsnFormat::F35c:
    case InsnFormat::F3rc:
        return 3;
    case InsnFormat::F45cc:
    case InsnFormat::F4rcc:
        return 4;
    case InsnFormat::F51l:
        return 5;
    case InsnFormat::Unknown:
    case InsnFormat::Payload:
        return 0;
    }
    return 0;
}

const OpcodeInfo& opcodeInfo(ca::u8 opcode) noexcept
{
    return kOpcodes[opcode];
}

const char* to_string(InsnFormat format) noexcept
{
    switch (format) {
    case InsnFormat::Unknown:
        return "unknown";
    case InsnFormat::F10x:
        return "10x";
    case InsnFormat::F12x:
        return "12x";
    case InsnFormat::F11n:
        return "11n";
    case InsnFormat::F11x:
        return "11x";
    case InsnFormat::F10t:
        return "10t";
    case InsnFormat::F20t:
        return "20t";
    case InsnFormat::F22x:
        return "22x";
    case InsnFormat::F21t:
        return "21t";
    case InsnFormat::F21s:
        return "21s";
    case InsnFormat::F21h:
        return "21h";
    case InsnFormat::F21c:
        return "21c";
    case InsnFormat::F23x:
        return "23x";
    case InsnFormat::F22b:
        return "22b";
    case InsnFormat::F22t:
        return "22t";
    case InsnFormat::F22s:
        return "22s";
    case InsnFormat::F22c:
        return "22c";
    case InsnFormat::F30t:
        return "30t";
    case InsnFormat::F32x:
        return "32x";
    case InsnFormat::F31i:
        return "31i";
    case InsnFormat::F31t:
        return "31t";
    case InsnFormat::F31c:
        return "31c";
    case InsnFormat::F35c:
        return "35c";
    case InsnFormat::F3rc:
        return "3rc";
    case InsnFormat::F45cc:
        return "45cc";
    case InsnFormat::F4rcc:
        return "4rcc";
    case InsnFormat::F51l:
        return "51l";
    case InsnFormat::Payload:
        return "payload";
    }
    return "unknown";
}

}   // namespace dex::core
