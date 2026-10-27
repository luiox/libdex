/// @file        method_editor.hpp
/// @brief       方法体构建门面：CodeUnit → 可注入 BuildOptions 的方法体。
///
/// 与 libjbc 的 MethodEditor 同一职责：把「建 CodeUnit → lower → 备好
/// CodeItem/insns」的四段接线压成一次 commit。只压缩接线层数，错误模型
/// 不变：每个可失败操作当场返回 Result，无 sticky 失败态、无析构自动提交。
///
/// 编排（intern 类/名字/proto、addMethod、push classDefs、把产物放进
/// BuildOptions::methodAdditions）是调用方或 libsmali 的事——本门面不碰
/// ID 表，保持与增量路径的护栏互斥性清晰。
#pragma once

#include "dex/core/code_dom.hpp"

namespace dex::core {

/// @brief commit 的产物：可直接放进 @ref BuildOptions::methodAdditions，
///        或配成 @ref CodeReplacement 覆盖既有方法体。
struct MethodBody
{
    CodeItem item;              ///< 头部计数与 tries/handlers 模型
    std::vector<ca::u8> insns;  ///< 已编码指令区，长度 = item.insnsSize * 2
};

/// @brief 单方法体编辑器。
class MethodEditor
{
public:
    /// @brief 以 code_item 头部三计数开编辑器；寄存器域后续可经
    ///        @ref unit() 的 setter 调整。
    MethodEditor(ca::u16 registersSize, ca::u16 insSize, ca::u16 outsSize)
    {
        unit_.setRegistersSize(registersSize);
        unit_.setInsSize(insSize);
        unit_.setOutsSize(outsSize);
    }

    /// @brief 直接暴露编辑单元：append/insertBefore/label/try 全套原语。
    CodeUnit& unit() noexcept { return unit_; }

    /// @brief lower 并产出方法体。payload 自动对齐（可见地插入 nop 槽）。
    ///        失败时编辑器内容保持原样，可继续修或放弃。
    Result<MethodBody, CodeDomError> commit();

private:
    CodeUnit unit_;
};

}   // namespace dex::core
