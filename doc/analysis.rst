.. _analysis:

CFG 与到达帧分析
================

状态：定稿。分析层从指令流派生 CFG 与到达帧，不回写模型、不做全程序视图。

CFG 构建
--------

``buildCfg`` 从解码指令流切块：leaders 取分支/switch 目标、try 边界、handler 入口与转移后继，块不跨 handler 集合变化点；流内边 + 异常边 + 前驱回填，悬垂目标不产假边（不崩溃、不误报）（analysis 头注）。

到达帧分析
----------

``analyzeFrames`` 是 best-effort 与 strict 同引擎的到达帧数据流：RegType 格上 cat1/cat2 按半寄存器配对（宽对两半都存 Long/Double，cat1 独立读写高半即 WidePairing）；引用带 type_idx，不同引用合并为引用顶，不解析继承层级（跨类归上层）。三条 ART 对齐的裁决：``const 0`` 的字面量零并入引用或 cat1 同族（ART Constant(0)）；冲突合并静默进帧、寄存器被读取才报 TypeConflict（ART 延迟判废——d8 的原地 ``aget`` 等惯用法不误报）；new-instance 的 UninitRef 由 invoke-direct ``<init>`` 调用初始化。move-result 必须紧跟 invoke/filled-new-array（DEX 无 jsr/ret，等价约束即此），目标类型按前驱返回描述符定型。monitor 深度在方法出口检查。不做全程序视图与 SMT。

.. _analysis-diagnostics:

帧分析诊断（strict 档）
-----------------------

``WidePairing``\（cat2 半寄存器被独立读写）、``MoveResultPair``\（move-result 未紧跟 invoke/filled-new-array）、``MonitorBalance``\（出口深度非零 / exit 无配对）、``TypeConflict``\（冲突合流的寄存器被读取——合并本身静默，与 ART 的延迟判废一致）、``BadOperand``\（寄存器越界 / 引用种类不符 / 参数个数不符）。best-effort 档同一引擎、零诊断；语料门要求真实 dex 全方法 strict 零诊断（analysis_test）。
