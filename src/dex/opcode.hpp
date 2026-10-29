/// @file        opcode.hpp
/// @brief       DEX 操作码与指令格式的静态元数据。
///
/// 元数据只描述编码形状：操作码名字、占用 code unit 数、索引类别。指令语义
/// （算术、调用分派、类型检查）不属于本库；上层需要的只是稳定的形状表。
///
/// 未被 dex-format 定义的操作码（0x3e–0x43、0x73、0x79–0x7a、0xe3–0xf9）
/// 保留为 format=Unknown 的条目，查询不抛异常、不返回空指针。
#pragma once

#include "libca/core/datatype.hpp"

namespace dex::core {

/// @brief instruction formats 全表（dex-format §instruction-formats）。
enum class InsnFormat : ca::u8 {
    Unknown = 0,
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
    /// @brief 伪指令（packed-switch / sparse-switch / fill-array-data payload）。
    Payload,
};

/// @brief 指令中的索引操作数指向哪张全局表。
enum class IndexKind : ca::u8 {
    None = 0,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
};

/// @brief 算术/转换指令的操作数族；None 表示非算术。
/// cat1 的整族（boolean/byte/char/short/int）统一记 Int，宽度按 Long/Double 判。
enum class DataType : ca::u8 {
    None = 0,
    Int,
    Long,
    Float,
    Double,
};


/// @brief 单个操作码的静态描述。
struct OpcodeInfo
{
    const char* name = "unused";
    InsnFormat format = InsnFormat::Unknown;
    IndexKind indexKind = IndexKind::None;
    /// 算术/转换三元组：目标族、第一源、第二源。unop 只用 src；2addr 的
    /// B 寄存器是第二源（A 兼目标与第一源）；lit 指令源恒 Int。
    DataType destType = DataType::None;
    DataType srcType = DataType::None;
    DataType src2Type = DataType::None;

    bool isDefined() const noexcept { return format != InsnFormat::Unknown; }
};

/// @brief payload 伪指令种类。
enum class PayloadKind : ca::u8 {
    None = 0,
    PackedSwitch,
    SparseSwitch,
    FillArrayData,
};

/// @brief 31t 操作码对应的 payload 种类；其余返回 None。
constexpr PayloadKind switchKindOf(ca::u8 opcode) noexcept
{
    switch (opcode) {
        case 0x2b:
            return PayloadKind::PackedSwitch;
        case 0x2c:
            return PayloadKind::SparseSwitch;
        case 0x2d:
            return PayloadKind::FillArrayData;
        default:
            return PayloadKind::None;
    }
}

/// @brief 定长格式占用的 code unit 数；Unknown 与 Payload 返回 0（宽度由内容决定）。
ca::u32 insnWidth(InsnFormat format) noexcept;

inline constexpr OpcodeInfo kOpcodes[256] = {
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
    OpcodeInfo{"neg-int", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::None},
    OpcodeInfo{"not-int", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::None},
    OpcodeInfo{"neg-long", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::None},
    OpcodeInfo{"not-long", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::None},
    OpcodeInfo{"neg-float", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::None},

    // 0x80–0x8f：类型转换
    OpcodeInfo{"neg-double", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::None},
    OpcodeInfo{"int-to-long", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Int, DataType::None},
    OpcodeInfo{"int-to-float", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Int, DataType::None},
    OpcodeInfo{"int-to-double", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Int, DataType::None},
    OpcodeInfo{"long-to-int", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Long, DataType::None},
    OpcodeInfo{"long-to-float", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Long, DataType::None},
    OpcodeInfo{"long-to-double", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Long, DataType::None},
    OpcodeInfo{"float-to-int", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Float, DataType::None},
    OpcodeInfo{"float-to-long", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Float, DataType::None},
    OpcodeInfo{"float-to-double", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Float, DataType::None},
    OpcodeInfo{"double-to-int", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Double, DataType::None},
    OpcodeInfo{"double-to-long", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Double, DataType::None},
    OpcodeInfo{"double-to-float", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Double, DataType::None},
    OpcodeInfo{"int-to-byte", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::None},
    OpcodeInfo{"int-to-char", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::None},
    OpcodeInfo{"int-to-short", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::None},

    // 0x90–0x9f：二元运算
    OpcodeInfo{"add-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"sub-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"mul-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"div-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rem-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"and-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"or-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"xor-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"shl-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"shr-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"ushr-int", InsnFormat::F23x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"add-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"sub-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"mul-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"div-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"rem-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},

    // 0xa0–0xaf：二元运算
    OpcodeInfo{"and-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"or-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"xor-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"shl-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"shr-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"ushr-long", InsnFormat::F23x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"add-float", InsnFormat::F23x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"sub-float", InsnFormat::F23x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"mul-float", InsnFormat::F23x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"div-float", InsnFormat::F23x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"rem-float", InsnFormat::F23x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"add-double", InsnFormat::F23x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"sub-double", InsnFormat::F23x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"mul-double", InsnFormat::F23x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"div-double", InsnFormat::F23x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"rem-double", InsnFormat::F23x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},

    // 0xb0–0xbf：/2addr 运算
    OpcodeInfo{"add-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"sub-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"mul-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"div-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rem-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"and-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"or-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"xor-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"shl-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"shr-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"ushr-int/2addr", InsnFormat::F12x, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"add-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"sub-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"mul-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"div-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"rem-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},

    // 0xc0–0xcf：/2addr 运算
    OpcodeInfo{"and-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"or-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"xor-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Long},
    OpcodeInfo{"shl-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"shr-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"ushr-long/2addr", InsnFormat::F12x, IndexKind::None, DataType::Long, DataType::Long, DataType::Int},
    OpcodeInfo{"add-float/2addr", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"sub-float/2addr", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"mul-float/2addr", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"div-float/2addr", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"rem-float/2addr", InsnFormat::F12x, IndexKind::None, DataType::Float, DataType::Float, DataType::Float},
    OpcodeInfo{"add-double/2addr", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"sub-double/2addr", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"mul-double/2addr", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"div-double/2addr", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},
    OpcodeInfo{"rem-double/2addr", InsnFormat::F12x, IndexKind::None, DataType::Double, DataType::Double, DataType::Double},

    // 0xd0–0xdf：lit16 / lit8
    OpcodeInfo{"add-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rsub-int", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"mul-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"div-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rem-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"and-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"or-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"xor-int/lit16", InsnFormat::F22s, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"add-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rsub-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"mul-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"div-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"rem-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"and-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"or-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"xor-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},

    // 0xe0–0xef：lit8 / 未定义
    OpcodeInfo{"shl-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"shr-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
    OpcodeInfo{"ushr-int/lit8", InsnFormat::F22b, IndexKind::None, DataType::Int, DataType::Int, DataType::Int},
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



/// @brief 格式名（诊断与测试输出用）。
const char* to_string(InsnFormat format) noexcept;

/// @brief 查询操作码元数据；未定义操作码返回 name="unused" 的条目。
constexpr const OpcodeInfo& opcodeInfo(ca::u8 opcode) noexcept
{
    return kOpcodes[opcode];
}

}   // namespace dex::core
