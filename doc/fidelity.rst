.. _fidelity:

保真契约与透传写回
==================

状态：定稿。DOM 对源字节的保真不变量与未修改写回的透传语义。修改后的写回走 ``buildDex``，两条布局路径的设计见 :ref:`rebuild`。

条目保真
--------

- 条目记录源区间（``ByteSpan raw``）；未建模 map section 记入 ``rawSections``。
- ``encoded_value`` 保存原始 ``value_arg``，非最小宽度也原样重编码。
- debug_info 的 header 与每条操作保留原始字节，包括非最小 ULEB/SLEB。
- 指令保留原始 code unit（``Insn::raw``），未用高位与 nop 变体按源字节写回。
- 共享的 type_list、annotation set/item、code、debug_info、class_data 按偏移去重。

透传写回
--------

未修改写回用 ``writeDex`` 原字节透传，连 checksum/signature 都不重算（writer 头注）。校验字段的语义与重算时机归 integrity；已修改模型的判定以条目编辑面为准，``buildDex`` 是修改后的唯一写回路径（:ref:`rebuild`）。
