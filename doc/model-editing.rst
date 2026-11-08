.. _model-editing:

编辑应用层
==========

状态：定稿。``buildDex`` 的编辑应用语义（builder_edit 头注）：成员注入、注解覆盖、静态初值、删除与剥离如何进入重建。ID 表级的追加与裁剪见 :ref:`id-tables`；这些编辑对增量前提的影响见 :ref:`rebuild-incremental`。

成员注入
--------

成员注入走 ``BuildOptions::fieldAdditions``/``methodAdditions``：成员追加到目标 classDef 的 class_data 副本（类没有 class_data 时新建），新增方法体与替换体一起进入统一 code 单元，按新方法索引排序后落位，保证二次重建固定。静态字段增删会按新的字段顺序重建 static_values：新增字段填类型默认值（可被 ``setStaticFieldValue`` 覆盖），删除字段去掉对应槽位，尾部省略的默认槽位按规范允许保留省略或补默认值。新增成员的注解与参数注解暂不支持。

新增类与注解覆盖
----------------

新增类不需要额外 API：向 ``classDefs`` 追加 ClassDef，再用成员注入填 class_data，接口列表用 ``setClassInterfaces`` 新建。注解用覆盖 API 挂上：``addAnnotationItem`` 把注解项（可见性 + encoded_annotation，含嵌套值）按内容去重入池并校验全部表索引、把索引型载荷宽度改到最小；``setClassAnnotations``/``setFieldAnnotations``/``setMethodAnnotations``/``setParameterAnnotations`` 按成员覆盖，空集表示清空条目。重建把覆盖与源 annotations_directory 逐类合并成生效目录再发射：未覆盖成员沿用源 set/ref_list，被覆盖成员换自有条目，只有生效目录引用的 set 与 item 才落盘（孤儿不发射），二次重建保持固定点。覆盖目标必须在生效 class_data（含注入成员、扣除删除）中有定义，参数注解长度须等于 proto 参数个数；与 ``stripAnnotations`` 同时使用返回 ``InvalidModel``。

静态初值
--------

静态初值走 ``setStaticFieldValue(classDefIdx, fieldIdx, value)``：值类别须匹配字段类型（原始类型精确匹配，引用类型接受常量类载荷），全部载荷宽度归一到最小可用（数值按最小有/无符号宽度、浮点按尾部零字节、布尔按真值置位、索引按最小索引宽度）；引用悬垂返回 ``BadIndex``，归一后仍放不下（如 Byte 放大数）由重编码返回 ``Unencodable``。重建时编辑值替换源数组槽位或新增字段默认值，无源数组的类会物化出数组；目标不在生效静态字段集合（实例字段、删除字段、未定义字段）内返回 ``InvalidModel``。

删除与标志覆盖
--------------

删除类直接 erase ``classDefs``；删除成员走 ``removedFields``/``removedMethods``，只从 class_data 移除，ID 表条目不回收。删除静态字段会同步重建 static_values。删除后仍被指令引用的条目按 DEX 的外部引用处理，调用方负责一致性。

已有成员的 access_flags 可用 ``fieldAccessFlags``/``methodAccessFlags`` 覆盖：方法按新标志在直接/虚方法列表间搬移；字段禁止改变 ACC_STATIC，因为分组与 static_values 槽位按静态性固定。

元数据剥离
----------

元数据可以用 ``stripDebugInfo`` 与 ``stripAnnotations`` 整体剥离：前者不产出 debug_info 并把 code_item 的 debug_info_off 置 0，后者不产出注解族并把 class_def 的 annotations_off 置 0。剥离不影响 ID 表与指令。
