/// @file        method_editor.hpp
/// @brief       方法体中层编辑门面：指令/label/try/payload 走 CodeUnit，
///              debug 事件在本层记录、commit 时降级为 debug_info_item 字节。
///
/// 把「建 CodeUnit → lower → 备好 CodeItem/insns/debug」的接线压成一次
/// commit。只压缩接线层数，错误模型不变：每个可失败操作当场返回
/// Result，无 sticky 失败态、无析构自动提交。
///
/// 编排（intern 类/名字/proto、addMethod、push classDefs、把产物放进
/// BuildOptions::methodAdditions）是调用方或 libsmali 的事——本门面不碰
/// ID 表，保持与增量路径的护栏互斥性清晰。
#pragma once

#include <vector>

#include "dex/code_dom.hpp"

namespace dex::core {

/// @brief commit 的产物：可直接放进 @ref BuildOptions::methodAdditions，
///        或配成 @ref CodeReplacement 覆盖既有方法体。
struct MethodBody
{
    CodeItem item;              ///< 头部计数与 tries/handlers 模型
    std::vector<ca::u8> insns;  ///< 已编码指令区，长度 = item.insnsSize * 2

    /// @brief 预编码的 debug_info_item 字节（从零构建的文件没有源字节，
    ///        builder 无法 lazy 解码）。空表示无 debug。
    std::vector<ca::u8> debugBytes;
};

/// @brief 单方法体编辑器。
class MethodEditor
{
public:
    /// @brief debug 事件种类，与 debug_info_item 的操作码一一对应。
    enum class DbgKind : ca::u8 {
        Line,
        StartLocal,
        StartLocalExtended,
        EndLocal,
        RestartLocal,
        PrologueEnd,
        EpilogueBegin,
    };

    /// @brief 以 code_item 头部三计数开编辑器；寄存器域后续可经
    ///        @ref unit() 的 setter 调整。
    MethodEditor(ca::u16 registersSize, ca::u16 insSize, ca::u16 outsSize)
    {
        unit_.setRegistersSize(registersSize);
        unit_.setInsSize(insSize);
        unit_.setOutsSize(outsSize);
    }

    /// @brief 直接暴露编辑单元：label/try/payload/分支全套原语。
    ///
    /// debug 锚点只随 @ref append 走；直接 unit().append 追加指令不更新
    /// 锚点，混用两者时事件会锚到更早的槽。
    CodeUnit& unit() noexcept { return unit_; }

    /// @brief 追加到程序序末尾，并把它设为后续 debug 事件的锚点。
    ///        payload 指令同时给出自持载荷字节。
    InsnId append(Insn insn, std::vector<ca::u8> payloadStorage = std::vector<ca::u8>{});

    /// @brief lower 并产出方法体。payload 自动对齐（可见地插入 nop 槽），
    ///        debug 事件按 lower 后的地址定锚、排序并降级为 ops 字节。
    ///        失败时编辑器内容保持原样，可继续修或放弃。
    Result<MethodBody, CodeDomError> commit();

    // ---- debug 事件：锚 = 最近一次 append 的槽之后；尚无指令 = 方法开头 ----

    void debugLine(ca::i32 line);
    /// @brief @p sigIdx 传 kNoIndex 即普通 StartLocal，否则 StartLocalExtended。
    void debugStartLocal(ca::u32 reg, ca::u32 nameIdx, ca::u32 typeIdx, ca::u32 sigIdx);
    void debugEndLocal(ca::u32 reg);
    void debugRestartLocal(ca::u32 reg);
    void debugPrologueEnd();
    void debugEpilogueBegin();
    /// @brief 参数名表（已 intern 的字符串下标；kNoIndex = 无名参数）。
    void setDebugParamNames(std::vector<ca::u32> nameIdx);

    /// @brief debug 索引哨兵：无名参数/无签名。
    static constexpr ca::u32 kNoIndex = 0xFFFFFFFFu;

private:
    struct DbgEvent
    {
        DbgKind kind = DbgKind::Line;
        InsnId after{nullptr, kEndSlot, 0};  ///< 事件落在此槽之后；kEndSlot = 方法开头
        ca::i32 line = 0;
        ca::u32 reg = 0;
        ca::u32 nameIdx = 0;
        ca::u32 typeIdx = 0;
        ca::u32 sigIdx = 0;
    };

    CodeUnit unit_;
    InsnId lastAppended_{nullptr, kEndSlot, 0};
    std::vector<DbgEvent> debug_;
    std::vector<ca::u32> paramNames_;
};

}   // namespace dex::core
