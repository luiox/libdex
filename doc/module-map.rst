.. _module-map:

libdex 模块地图
===============

模块面导航：每个头文件（及其 ``@defgroup`` 组）属于哪个域、职责边界是什么、宏观规格在哪一篇。微观契约（参数、返回、失败模式）在对应头注里，本表只做落点。域内设计裁决见「规格」列指向的篇章。

原语层
------

.. _module-map-primitives:

bytes / leb128 / format / descriptor / dex（统一入口头）。字节区段与随机访问、ULEB128 读取面、格式层常量、描述符解析——它们没有独立规格页，边界即头注；唯一上升为宏观裁决的是 descriptor 的范围：type 层只解析字段类型与方法描述符，不查 ID 表、不解析泛型签名（descriptor 头注）。

骨架与读入
----------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - 模块
     - 职责
     - 规格
   * - reader
     - 骨架解析入口：eager 骨架 + lazy 数据
     - :ref:`architecture-eager-lazy`\（分档语义 :ref:`errors`\）
   * - dex_file
     - 单 DexFile DOM：模型本体、ID 表与懒解码缓存
     - :ref:`architecture-ownership`
   * - error
     - 读取/写出错误码、解析状态与诊断收集
     - :ref:`errors`
   * - integrity
     - 头校验字段：adler32 与 SHA-1
     - :ref:`fidelity`

条目 codec
----------

解析与精确重编码同住一个文件，保真规则统一在 :ref:`fidelity`；条目族之间不互相依赖。

.. list-table::
   :header-rows: 1
   :widths: auto

   * - 模块
     - 职责
     - 规格
   * - annotation
     - 注解族数据条目：annotation_item / set_item / ref_list / directory
     - :ref:`fidelity`、覆盖语义 :ref:`model-editing`
   * - encoded_value
     - encoded_value / encoded_annotation 的递归 DOM
     - :ref:`fidelity`
   * - class_data
     - class_data_item 的结构解码与精确重编码
     - :ref:`rebuild`、成员编辑 :ref:`model-editing`
   * - code_item
     - code_item 的结构解码与精确重编码
     - :ref:`fidelity`
   * - debug_info
     - debug_info_item 的结构解码与精确重编码
     - :ref:`fidelity`、编辑定锚 :ref:`insns-method-editor`

指令与方法体
------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - 模块
     - 职责
     - 规格
   * - insn
     - 指令 DOM：逐条解码为定长结构
     - :ref:`insns-codec`
   * - opcode
     - 操作码与指令格式的静态元数据（单源表）
     - :ref:`insns-opcode`
   * - insn_edit
     - 指令编辑原语：分支目标、寄存器域、地址重算与 payload 构造
     - :ref:`insns-primitives`
   * - code_dom
     - 方法体结构编辑模型：CodeUnit + label + 值句柄
     - :ref:`architecture-layering`
   * - method_editor
     - 方法体中层编辑门面：接线 CodeDom 与 debug 事件
     - :ref:`insns-method-editor`

重建与写回
----------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - 模块
     - 职责
     - 规格
   * - writer
     - 未修改透传写回
     - :ref:`fidelity`
   * - builder
     - 整文件 canonical 重建：布局、偏移回填、map_list 与校验字段
     - :ref:`rebuild-canonical`
   * - builder_edit
     - 编辑应用层：canonical 与增量共享的编辑校验与合成
     - :ref:`model-editing`
   * - vacuum
     - ID 表引用闭包：计算裁剪需保留的条目集合
     - :ref:`id-tables`

分析
----

analysis 独立成域：CFG 与到达帧从指令流派生，不回写模型。见 :ref:`analysis`。

文本层（libsmali）
------------------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - 模块
     - 职责
     - 规格
   * - disassemble
     - 反汇编器：DexFile → smali 文本
     - :ref:`smali-adapter`
   * - assemble
     - 汇编器：smali 文本 → DexFile 编辑
     - :ref:`smali-adapter`
   * - smali_opcodes
     - 共享表：opcode ↔ 助记符、格式与 access flags
     - :ref:`insns-opcode`\（与 core 单源表锁死）

对拍与工具
----------

仓内工具（oracle / corpus）不属库面，契约见 :ref:`oracle`。
