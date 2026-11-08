.. _id-tables:

ID 表与字符串池
===============

状态：定稿。六张 ID 表的排序要求、canonical 池合成、条目追加与裁剪。表级编辑对重建路径的影响见 :ref:`rebuild-incremental`；成员/注解/静态初值等编辑应用见 :ref:`model-editing`。

排序与重写
----------

DEX 要求 string_ids 按 UTF-16 排序，type/proto/field/method 按各自键排序。新增或重命名不能只追加，必须重排序并重写所有内嵌索引。

字符串层：``internString`` 接受 MUTF-8，``internUtf8`` 接受标准 UTF-8，返回可写入 ``nameIdx``/``sourceFileIdx``/指令索引的 string 索引。``buildDex`` 把所有源字符串与自有字符串合成 canonical 池：按 UTF-16 code unit 排序、去重、建立旧→新映射，再重写 type/proto/field/method 的字符串索引、class_def 的 source_file_idx、const-string/const-string/jumbo、debug_info 的参数名与 SET_FILE、encoded_value 的 String、注解元素名。

类型与成员层：type_ids 按描述符重排，proto_ids 按返回类型、参数个数与逐参数（AOSP 规则）重排，field_ids/method_ids 按 (class, name, type/proto) 重排，class_defs 按 class_idx 重排。type_list 重新编码；class_data 的成员索引按新索引重排四个列表，注解目录的成员索引、指令、catch handler、debug_info 的局部变量类型、method_handle 与 encoded_value 的索引全部重写。重命名不再要求保持原表顺序。

表索引发生变化而仍保留未建模 section 时返回 ``UnmappedRawSection``，因为无法迁移其中可能存在的索引；显式关闭 ``keepUnknownSections`` 才能继续。const-string 不自动提升为 jumbo，新索引超出 16 位返回 ``Unencodable``，形态选择仍归 adapter（:ref:`smali-adapter`）。

class_defs 可以删除与重排；删类不回收 ID 表条目。容量：type/proto/field/method 各 65536，string 是 u32；``buildDex`` 在入口检查容量与表内索引，越界返回 ``InvalidModel``。

条目追加
--------

ID 表追加走 ``addType``/``addProto``/``addField``/``addMethod``：按内容复用已有条目，返回索引，表满返回 ``IdTableFull``。proto 也可以按参数列表直建：``addProtoWithParams(returnTypeIdx, parameters)`` 自动推导并 intern shorty（对象与数组记 'L'，参数不允许 void），与既有 proto 按内容去重；参数列表存入自有 type_list 池。``addTypeList`` 直接入池（池内按内容去重，空列表返回 kNoIndex 不占位），``setClassInterfaces(classDefIdx, interfaces)`` 用自有列表覆盖类接口。重建时自有列表发射为新 type_list 并回填真实的偏移；``ProtoId``/``ClassDef`` 的 owned 标志区分取池下标还是源偏移，池下标悬垂返回 ``InvalidModel``，``protoParameters``/``interfaces`` 对 owned 条目返回池内视图。

引用闭包裁剪
------------

ID 表裁剪走 vacuum：以 class_defs 为根计算引用闭包，剔除未引用的 string/type/proto/field/method 表项并全量重写引用（vacuum 头注）；class_defs 不裁，仅 canonical 路径生效。
