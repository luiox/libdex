.. _rebuild:

重建路径：canonical 与增量
==========================

状态：定稿。``buildDex`` 的两条布局路径与各自的前提、产物承诺。保真不变量见 :ref:`fidelity`；编辑如何进入重建见 :ref:`model-editing`。

.. _rebuild-canonical:

canonical 重建
--------------

canonical 是默认路径：整文件重排成规范布局，回填文件偏移，重建 map_list，重算 adler32 与 SHA-1。

只输出可达条目，不可达的建模条目会丢弃；string_data 原字节复制，其余条目精确重编码。未建模 section 默认透传，可选择丢弃；其中若含绝对偏移不会回填。非空 link 区返回 ``NotModeled``；041 的 canonical 重建已解冻：header 扩到 0x78，container 字段按独立文件约定重置 ``(file_size, 0)``\（canonical 产物是单文件，不继承容器上下文），增量路径在实物语料复核前保持 ``NotModeled``。

canonical 重排伴随 ID 表重排与全量索引重写，规则与限制见 :ref:`id-tables`。

.. _rebuild-incremental:

增量重建
--------

incremental 由 ``BuildOptions::incremental`` 选择：保留源布局，只重编码被改条目，为的是大文件上少量编辑的写回成本与输出稳定性（builder 头注）。

增量模式的前提是**编辑不触及 ID 表**：``stringIds``/``typeIds``/``protoIds``/``fieldIds``/``methodIds`` 的条目数与内容必须和源一致。检测到表级编辑（intern 过字符串、``addType``/``addProto``/``addField``/``addMethod`` 追加过条目、``addProtoWithParams`` 用过自有参数表）返回 ``NotIncremental``，调用方应改走 canonical。``classDefs`` 允许 erase（类删除）；手工改写 ID 表字段值是调用方违约，产物未定义。

- **发现**：从 DOM 引用图出发枚举全部源条目（含共享去重），再对六类自描述段（type_list、annotation set/ref list、annotation_item、encoded_array、debug_info）按 map 声明的段范围逐项走查补齐，工具会发射无人引用的孤儿条目（如 d8 为无注解类生成的空 annotation_set_item），漏掉它们会改变 map 计数与 checksum；条目间按 kind 对齐（如 type_list 的 4 字节），段尾对齐 padding 交给 gap。按源偏移排序；条目之间的空隙作为 gap 原样保留，canonical 会丢弃的不可达条目与未知填充在增量模式不丢。
- **发射集合**：编辑后引用图仍可达的条目。被编辑断开引用的源条目删除（成员删除后无人引用的 code_item、类删除、``stripDebugInfo``/``stripAnnotations``、注解清空后的孤儿 set）。
- **透传判定**：未被编辑且内部引用的偏移映射不变的条目按源字节透传，不解码内容、不重编码。string_data、debug_info、指令区、annotation_item、encoded_array 与三张纯索引 ID 表天然没有偏移引用，永远透传（除非删除）；含偏移引用的定长条目（string_ids、proto_ids、class_defs、call_site_ids、注解 set/ref_list/directory、code_item 的 debug_info_off）按新映射重发射；class_data 的 code_off 是 ULEB 变长，偏移变化触发重编码。
- **布局**：条目与 gap 按源偏移顺序线性平移；新条目（替换方法体、注入方法体、自有 type_list、注解覆盖、物化静态初值）追加在同类源条目之后，无同类时落在 map_list 之前；4 对齐条目在前导 gap 尾补零。ULEB 宽度随偏移变化会再次改变 class_data 大小，布局迭代至多 4 轮求固定点，不收敛返回 ``Unencodable``。
- **map_list 与 header**：map_list 按源条目顺序重发射，size/offset 更新，无条目的 section 删条目、新 section 按 type 值插入；header 透传源字节后回填变化字段（file_size、map_off、表偏移、data_off/data_size）并重算 checksum/SHA-1。
- **固定点**：无编辑的增量重建逐字节返回源文件（源自身 checksum/signature 一致时）；有编辑时二次增量稳定。
- 索引不动，因此未建模 section 的保留不再与索引重排冲突；section 整体平移，内部绝对偏移不回填，与 canonical 透传语义相同。
