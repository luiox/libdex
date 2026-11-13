.. _insns:

指令与方法体
============

状态：定稿。指令 codec、操作码单源、方法体中层门面与编辑原语的分工。分层位置见 :ref:`architecture-layering`；文本层对形态选择的使用见 :ref:`smali-adapter`。

.. _insns-codec:

解码与编码
----------

``decodeInsns`` 覆盖 26 种定长格式与三类 payload，给出地址、宽度、寄存器、索引、立即数与分支偏移；未定义操作码返回错误（insn 头注）。

``encodeInsn``/``encodeInsns`` 按 opcode 的定长格式写回，域宽溢出返回 ``OperandOverflow``，payload 错位返回 ``MisalignedPayload``。不自动插 nop、不改变形态。

payload 不展开成 target 数组，保留源字节视图；switch target 相对 switch 指令地址。

.. _insns-opcode:

操作码单源
----------

操作码分类单源在 opcode 头注：``kOpcodes[256]`` 汇总名字、格式、索引表与算术/转换的 ``DataType`` 三元组（目标/两源，宽度按 Long/Double 判，移位与 lit 的第二源恒 Int）。libsmali 的助记表经编译期断言锁死与 ``kOpcodes`` 一致（smali_opcodes 头注）；analysis 的算术形状由表推导，不按区间复写。

.. _insns-method-editor:

方法体编辑门面
--------------

方法体中层门面是 method_editor 头注：``MethodEditor`` 把 CodeUnit → lower → MethodBody 三步合并成一个入口，debug 事件（行号/局部变量/prologue/epilogue/参数名）在编辑器记录，commit 时按 lower 后地址定锚并降级为 ``debug_info_item`` 字节，文本层不自己碰 debug 操作码编码。

.. _insns-primitives:

指令编辑原语
------------

库还给 adapter 提供编辑原语（insn_edit 头注）：``constFormFits``、``insnIndexLimit``、``insnBranchTarget``/``setInsnBranchTarget``、``recomputeInsnAddresses``，寄存器域的 ``insnRegisterLayout``/``insnRegisterAt``/``setInsnRegister``/``setInsnRegisterRange``/``insnRegisterCeiling`` 与批量 ``shiftInsnRegisters``/``remapInsnRegisters``，以及 payload 构造器 ``makePackedSwitchPayload``/``makeSparseSwitchPayload``/``makeFillArrayDataPayload``\（返回自包含的 ``PayloadInsn``，storage 移动不失效）。寄存器写入按格式域宽校验（4/8/16 位）；重映射对 range 格式要求映射在区间上是平移，不平移的重排需要改成 35c 形态，归 adapter。sparse 构造器要求 key 严格递增（ART 按二分查找解释）。payload 标识取规范值 0x0100/0x0200/0x0300；0x0101 是 ``move vA,vB`` 的合法编码，不能当 packed-switch 标识（此前版本曾写反，真实语料的 move 指令被误判 payload 而报错）。label、CFG 与 const 形态选择仍归 adapter。
