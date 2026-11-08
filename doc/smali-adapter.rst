.. _smali-adapter:

libsmali 文本适配层
===================

状态：定稿。libsmali 是 DEX 与 smali 文本的互转层，库内唯一的 adapter：反汇编 DexFile → baksmali 兼容文法子集的 ``.smali`` 文本（disassemble 头注），汇编文本 → DexFile 编辑（assemble 头注）。它建在库内 CodeDom 上（:ref:`architecture-layering`），不在库外私养第二套方法体模型。

往返封闭与文法边界
------------------

文法以反汇编器自产文本为准做往返封闭，baksmali 特有而本库不发射的指令归已知边界。

形态选择归 adapter
------------------

``const/4``、``const/16`` vs ``const``、分支 10t/20t/30t、``const-string`` vs ``const-string/jumbo`` 这类形态选择在汇编器里按字面量与距离选择——这是 adapter 的职责，core 的「不合并、不提升」裁决不变（:ref:`insns-codec`）。库按调用方给定的 opcode 精确编码，不做合并或提升；不同需求对应不同 adapter，库不绑定其中一种。
