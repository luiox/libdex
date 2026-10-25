# libdex 设计

状态：施工中，未发布。本文只记边界、契约与裁决；实现进度见 [dev_plan](../dev_plan.md)。

## 定位

libdex 是 DEX 字节核：输入单个 `.dex`，输出保真 DOM 与写回字节。所有权单位是单 DexFile，不持有 APK、不持有多 dex 集合；容器与跨文件索引归上层。

## 分层

库只有两层：保真 DOM 与逐条目 codec，不定义方法体 AST。

`const/4`、`const/16`、`const-string/jumbo` 这类形态选择属于使用方 adapter。库按调用方给定的 opcode 精确编码，不做合并或提升；不同需求对应不同 adapter，库不绑定其中一种。

## 所有权

一个 DexFile 拥有源字节、骨架和全部懒解码产物，析构一次回收。MUTF-8、type_list、insns 的视图指向模型自有字节；`internString`/`internUtf8` 追加的字符串存在 DexFile 的自有池里，与源字符串走同一套懒解码入口。

reader 默认复制入参；关闭复制时借用调用方 buffer，其生命周期必须覆盖模型。公共 API 不返回调用方需要 delete 的指针。

## eager 与 lazy

eager：header、map_list、五张 ID 表、class_defs、call_site_id、method_handle。

lazy：string_data、class_data、code_item、type_list、注解族、encoded_array、debug_info。结果按偏移缓存；失败结果也缓存；`peek` 不解码。

## 保真

- 条目记录源区间（`ByteSpan raw`）；未建模 map section 记入 `rawSections`。
- `encoded_value` 保存原始 `value_arg`，非最小宽度也原样重编码。
- debug_info 的 header 与每条操作保留原始字节，包括非最小 ULEB/SLEB。
- 指令保留原始 code unit（`Insn::raw`），未用高位与 nop 变体按源字节写回。
- 共享的 type_list、annotation set/item、code、debug_info、class_data 按偏移去重。

未修改写回用 `writeDex` 原字节透传，连 checksum/signature 都不重算。`buildDex` 是修改后的唯一写回路径：按 canonical 布局重排，回填文件偏移，重建 map_list，重算 adler32 与 SHA-1。

`buildDex` 只输出可达条目，不可达的建模条目会丢弃；string_data 原字节复制，其余条目精确重编码。未建模 section 默认透传，可选择丢弃；其中若含绝对偏移不会回填。041 与非空 link 区返回 `NotModeled`。

## ID 表与字符串池

DEX 要求 string_ids 按 UTF-16 排序，type/proto/field/method 按各自键排序。新增或重命名不能只追加，必须重排序并重写所有内嵌索引。

字符串层：`internString` 接受 MUTF-8，`internUtf8` 接受标准 UTF-8，返回可写入 `nameIdx`/`sourceFileIdx`/指令索引的 string 索引。`buildDex` 把所有源字符串与自有字符串合成 canonical 池：按 UTF-16 code unit 排序、去重、建立旧→新映射，再重写 type/proto/field/method 的字符串索引、class_def 的 source_file_idx、const-string/const-string/jumbo、debug_info 的参数名与 SET_FILE、encoded_value 的 String、注解元素名。

类型与成员层：type_ids 按描述符重排，proto_ids 按返回类型、参数个数与逐参数（AOSP 规则）重排，field_ids/method_ids 按 (class, name, type/proto) 重排，class_defs 按 class_idx 重排。type_list 重新编码；class_data 的成员索引按新索引重排四个列表，注解目录的成员索引、指令、catch handler、debug_info 的局部变量类型、method_handle 与 encoded_value 的索引全部重写。重命名不再要求保持原表顺序。

表索引发生变化而仍保留未建模 section 时返回 `UnmappedRawSection`，因为无法迁移其中可能存在的索引；显式关闭 `keepUnknownSections` 才能继续。const-string 不自动提升为 jumbo，新索引超出 16 位返回 `Unencodable`，形态选择仍归 adapter。

class_defs 可以删除与重排；删类不回收 ID 表条目。容量：type/proto/field/method 各 65536，string 是 u32；`buildDex` 在入口检查容量与表内索引，越界返回 `InvalidModel`。

ID 表追加走 `addType`/`addProto`/`addField`/`addMethod`：按内容复用已有条目，返回索引，表满返回 `IdTableFull`。proto 也可以按参数列表直建：`addProtoWithParams(returnTypeIdx, parameters)` 自动推导并 intern shorty（对象与数组记 'L'，参数不允许 void），与既有 proto 按内容去重；参数列表存入自有 type_list 池。`addTypeList` 直接入池（池内按内容去重，空列表返回 kNoIndex 不占位），`setClassInterfaces(classDefIdx, interfaces)` 用自有列表覆盖类接口。重建时自有列表发射为新 type_list 并回填真实偏移；`ProtoId`/`ClassDef` 的 owned 标志区分取池下标还是源偏移，池下标悬垂返回 `InvalidModel`，`protoParameters`/`interfaces` 对 owned 条目返回池内视图。

成员注入走 `BuildOptions::fieldAdditions`/`methodAdditions`：成员追加到目标 classDef 的 class_data 副本（类没有 class_data 时新建），新增方法体与替换体一起进入统一 code 单元，按新方法索引排序后落位，保证二次重建固定。静态字段增删会按新的字段顺序重建 static_values：新增字段填类型默认值（可被 `setStaticFieldValue` 覆盖），删除字段去掉对应槽位，尾部省略的默认槽位按规范允许保留省略或补默认值。新增成员的注解与参数注解暂不支持。

新增类不需要额外 API：向 `classDefs` 追加 ClassDef，再用成员注入填 class_data，接口列表用 `setClassInterfaces` 新建。注解用覆盖 API 挂上：`addAnnotationItem` 把注解项（可见性 + encoded_annotation，含嵌套值）按内容去重入池并校验全部表索引、把索引型载荷宽度改到最小；`setClassAnnotations`/`setFieldAnnotations`/`setMethodAnnotations`/`setParameterAnnotations` 按成员覆盖，空集表示清空条目。重建把覆盖与源 annotations_directory 逐类合并成生效目录再发射：未覆盖成员沿用源 set/ref_list，被覆盖成员换自有条目，只有生效目录引用的 set 与 item 才落盘（孤儿不发射），二次重建保持固定点。覆盖目标必须在生效 class_data（含注入成员、扣除删除）中有定义，参数注解长度须等于 proto 参数个数；与 `stripAnnotations` 同时使用返回 `InvalidModel`。

静态初值走 `setStaticFieldValue(classDefIdx, fieldIdx, value)`：值类别须匹配字段类型（原始类型精确匹配，引用类型接受常量类载荷），全部载荷宽度归一到最小可用（数值按最小有/无符号宽度、浮点按尾部零字节、布尔按真值置位、索引按最小索引宽度）；引用悬垂返回 `BadIndex`，归一后仍放不下（如 Byte 放大数）由重编码返回 `Unencodable`。重建时编辑值替换源数组槽位或新增字段默认值，无源数组的类会物化出数组；目标不在生效静态字段集合（实例字段、删除字段、未定义字段）内返回 `InvalidModel`。

删除类直接 erase `classDefs`；删除成员走 `removedFields`/`removedMethods`，只从 class_data 移除，ID 表条目不回收。删除静态字段会同步重建 static_values。删除后仍被指令引用的条目按 DEX 的外部引用处理，调用方负责一致性。

已有成员的 access_flags 可用 `fieldAccessFlags`/`methodAccessFlags` 覆盖：方法按新标志在直接/虚方法列表间搬移；字段禁止改变 ACC_STATIC，因为分组与 static_values 槽位按静态性固定。

元数据可以用 `stripDebugInfo` 与 `stripAnnotations` 整体剥离：前者不产出 debug_info 并把 code_item 的 debug_info_off 置 0，后者不产出注解族并把 class_def 的 annotations_off 置 0。剥离不影响 ID 表与指令。

## 错误

错误走 `Result`，不抛异常。结构性问题返回 Err；语义问题（校验和不符、悬垂索引、map 计数不符）记诊断并将 `ParseState` 置 `Recovered`，模型仍可读。

`ParseState` 只有 `Validated` 与 `Recovered`；结构损坏不产出半截模型。

## 指令

`decodeInsns` 覆盖 26 种定长格式与三类 payload，给出地址、宽度、寄存器、索引、立即数与分支偏移；未定义操作码返回错误。

`encodeInsn`/`encodeInsns` 按 opcode 的定长格式写回，域宽溢出返回 `OperandOverflow`，payload 错位返回 `MisalignedPayload`。不自动插 nop、不改变形态。

库还给 adapter 提供编辑原语：`constFormFits`、`insnIndexLimit`、`insnBranchTarget`/`setInsnBranchTarget`、`recomputeInsnAddresses`，寄存器域的 `insnRegisterLayout`/`insnRegisterAt`/`setInsnRegister`/`setInsnRegisterRange`/`insnRegisterCeiling` 与批量 `shiftInsnRegisters`/`remapInsnRegisters`，以及 payload 构造器 `makePackedSwitchPayload`/`makeSparseSwitchPayload`/`makeFillArrayDataPayload`（返回自包含的 `PayloadInsn`，storage 移动不失效）。寄存器写入按格式域宽校验（4/8/16 位）；重映射对 range 格式要求映射在区间上是平移，不平移的重排需要改成 35c 形态，归 adapter。sparse 构造器要求 key 严格递增（ART 按二分查找解释）。payload 标识取规范值 0x0101/0x0202/0x0300。label、CFG 与 const 形态选择仍归 adapter。

payload 不展开成 target 数组，保留源字节视图；switch target 相对 switch 指令地址。

## 类型与容器

type 层只解析字段类型与方法描述符，不查 ID 表、不解析泛型签名。

单文件职责；classes2.dex、APK 容器、resources.arsc 与 AXML 都在库外。

## 对拍

文本 oracle 是 baksmali 2.5.2（dexlib2）：原文件与 `buildDex` 产物分别反汇编，smali 文本必须一致。canonical 重建按规范重排 method_ids 后，class_data 的方法顺序会变；方法块顺序不是语义，脚本按块排序后再 diff，字段、注解与指令文本仍逐字节比较。它覆盖指令、try/catch、注解、静态初值、debug 行号与访问标志。

baksmali 不覆盖未建模 section，也不等于 ART 接受；与 AOSP DEX 规范冲突时以规范为准。ReDex 与 ART 实机验证尚未接线。

真实语料不入库，通过 `LIBDEX_REAL_DEX_DIR` 注入；第三方 APK 只允许哈希清单与复现脚本。

## 不做

- odex / vdex / art / compact dex。
- APK、resources.arsc、AXML 与多 dex 模型。
- ID 表条目新增与删除（字符串 intern 除外）；压缩与 vacuum。
- visitor 形状与库内方法体 AST。
- opcode 形态合并或自动提升。
- 修改后字节 diff 最小化。

## 相关

- [README](../README.md)：构建与最小示例。
- [dev_plan](../dev_plan.md)：实现进度与下一步。
