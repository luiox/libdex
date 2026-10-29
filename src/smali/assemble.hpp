/// @file        assemble.hpp
/// @brief       libsmali 汇编器：smali 文本 → DexFile 编辑。
///
/// 与反汇编器的文法互为镜像（含整数类型后缀 b/s/L、浮点位模式 0x..F/D、
/// payload/try/debug 指令块）。汇编只往模型追加：字符串/类型/proto/字段/
/// 方法经 intern 家族去重入表，成员经 BuildOptions 注入，类 push_back 到
/// classDefs；产出字节交给 buildDex（canonical 重排由它负责）。
///
/// 从零构建文件：
///   DexFile dex = *DexFile::createEmpty(35);
///   SmaliAssembler assembler(dex);
///   assembler.assembleClass(text);          // 逐类
///   buildDex(dex, assembler.options());     // 产出字节
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <string_view>

#include "libca/core/result.hpp"

#include "dex/builder.hpp"
#include "dex/dex_file.hpp"

namespace dex::smali {

using core::Result;

/// @brief 汇编失败原因。
enum class AsmErrorCode {
    Ok = 0,
    Syntax,            ///< 行解析失败（缺 token、括号不配等）
    UnknownDirective,  ///< 未认识的指令块
    UnknownMnemonic,   ///< 未知操作码助记符
    BadRegister,       ///< 寄存器编号/前缀非法，或超出 .registers 域
    BadLabel,          ///< label 未定义即被引用（branch/try/handler）
    BadRef,            ///< 字段/方法/类型引用解析失败
    BadValue,          ///< 字面量/注解值解析失败
    Overflow,          ///< 立即数/寄存器/偏移超出格式域宽
    Duplicate,         ///< 重复定义（同名 label 等）
    ModelError,        ///< 底层 intern/add* 返回错误
};

/// @brief 错误码的可读文本。
const char* to_string(AsmErrorCode e) noexcept;

/// @brief 汇编错误：码 + 行号 + 细节。
struct AsmError
{
    AsmErrorCode code = AsmErrorCode::Ok;
    ca::u32 line = 0;
    std::string detail;

    static AsmError make(AsmErrorCode c, ca::u32 line, std::string detail)
    {
        return AsmError{c, line, std::move(detail)};
    }
};

/// @brief 逐类汇编器；成员注入选项跨类累积，最后由调用方一次性 buildDex。
class SmaliAssembler
{
public:
    explicit SmaliAssembler(core::DexFile& dex) : dex_(dex)
    {
        // 文本重建走 d8 约定：static_values 裁掉尾部默认槽位（全默认则整组
        // 不写），保证反汇编(汇编(反汇编(x)))文本逐字节稳定。
        options_.trimTrailingStaticDefaults = true;
    }

    /// @brief 汇编一个类的文本，追加为新类；返回 class_def 下标。
    Result<ca::u32, AsmError> assembleClass(std::string_view text);

    /// @brief 累积的成员注入；与 buildDex 一次性配合。
    const core::BuildOptions& options() const noexcept { return options_; }

    core::BuildOptions& options() noexcept { return options_; }

private:
    core::DexFile& dex_;
    core::BuildOptions options_;
    ca::u32 superclassIdx_ = core::DexFile::kNoIndex;
    ca::u32 sourceFileIdx_ = core::DexFile::kNoIndex;
    std::vector<core::FieldAddition> deferredFieldAdditions_;
    std::vector<std::pair<ca::u32, std::vector<ca::u32>>> deferredFieldAnnotations_;
};

}   // namespace dex::smali
