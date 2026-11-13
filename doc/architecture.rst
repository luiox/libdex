.. _architecture:

libdex 总纲：定位、分层与所有权
===============================

状态：定稿。跨模块的总纲性裁决：libdex 是什么、分层边界在哪、所有权与解码时机如何约定。各模块的域内规格从 :doc:`module-map` 进入；范围外清单见 :doc:`non_goals`。

.. _architecture-positioning:

定位
----

libdex 是 DEX 字节核：输入单个 ``.dex``，输出保真 DOM 与写回字节。所有权单位是单 DexFile，不持有 APK、不持有多 dex 集合；容器与跨文件索引归上层。

.. _architecture-layering:

分层
----

库三层：保真 DOM、逐条目 codec、方法体 CodeDom；同仓另有 libsmali 文本层（:ref:`smali-adapter`）。源码布局与库目标对齐：``src/dex`` 是 libdex、``src/smali`` 是 libsmali，库内扁平不设子目录，模块化落在文件级，条目 codec 按条目族一个文件、解析与精确重编码同住（annotation / encoded_value / debug_info / insn / leb128 / class_data / code_item）；``dex_file`` 是文档层，负责骨架、ID 表与懒解码缓存，不含条目编解码。

CodeDom（code_dom 头注）是方法体的结构编辑模型：``CodeUnit`` 拥有指令槽表与程序序，分支/try/handler/payload 用 label 与值句柄（``InsnId{owner,slot,gen}``）引用，insert/replace/erase 后地址与 try 区间联动重算。它是 libsmali 与上层方法体编辑的唯一底座（:ref:`insns`）：libsmali 就是那个 adapter，建在库内 CodeDom 上，不在库外另维护第二套方法体模型。

.. _architecture-ownership:

所有权
------

一个 DexFile 拥有源字节、骨架和全部懒解码产物，析构一次回收（dex_file 头注）。MUTF-8、type_list、insns 的视图指向模型自有字节；``internString``/``internUtf8`` 追加的字符串存在 DexFile 的自有池里，与源字符串走同一套懒解码入口。

reader 默认复制入参；关闭复制时借用调用方 buffer，其生命周期必须覆盖模型。公共 API 不返回调用方需要 delete 的指针。

.. _architecture-eager-lazy:

eager 与 lazy
-------------

eager：header、map_list、五张 ID 表、class_defs、call_site_id、method_handle（reader 头注）。

lazy：string_data、class_data、code_item、type_list、注解族、encoded_array、debug_info。结果按偏移缓存；失败结果也缓存；``peek`` 不解码。

读入被拒 / 带病可读 / 延迟到访问的分档语义见 :ref:`errors`。
