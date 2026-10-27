# libdex 设计

状态：施工中，未发布。本文只记边界、契约与裁决；实现进度见 [dev_plan](../dev_plan.md)。

## 定位

libdex 是 DEX 字节核：输入单个 `.dex`，输出保真 DOM 与写回字节。所有权单位是单 DexFile，不持有 APK、不持有多 dex 集合；容器与跨文件索引归上层。

## 分层

库三层：保真 DOM、逐条目 codec、方法体 CodeDom；同仓另有 libsmali 文本层。条目 codec 按条目族一个文件、解析与精确重编码同住（annotation / encoded_value / debug_info / insn / leb128 / class_data / code_item）；`dex_file` 是文档层，负责骨架、ID 表与懒解码缓存，不含条目编解码。

CodeDom（`code_dom`）是方法体的结构编辑模型：`CodeUnit` 拥有指令槽表与程序序，分支/try/handler/payload 用 label 与值句柄（`InsnId{owner,slot,gen}`）引用，insert/replace/erase 后地址与 try 区间联动重算。它是 libsmali 与上层方法体编辑的唯一底座——smali 汇编没有 label 承载的模型做不出来，原「CFG 归 adapter」的裁决随 libsmali 入仓翻案：libsmali 是那个 adapter，建在库内 CodeDom 上，不在库外私养第二套方法体模型。

libsmali（`smali`）是 DEX 与 smali 文本的互转层：反汇编 DexFile → baksmali 兼容文法子集的 `.smali` 文本，汇编文本 → DexFile 编辑。形态选择（`const/4` vs `const/16` vs `const`、分支 10t/20t/30t）在汇编器里按字面量与距离选择——这是 adapter 的职责，core 的「不合并、不提升」裁决不变。文法以反汇编器自产文本为准做往返封闭，baksmali 特有而本库不发射的指令归已知边界。

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

## 增量重建

`buildDex` 有两条布局路径，由 `BuildOptions::incremental` 选择。canonical 是默认路径：整文件重排成规范布局。incremental 保留源布局，只重编码被改条目，为的是大文件上少量编辑的写回成本与输出稳定性。

增量模式的前提是**编辑不触及 ID 表**：`stringIds`/`typeIds`/`protoIds`/`fieldIds`/`methodIds` 的条目数与内容必须和源一致。检测到表级编辑（intern 过字符串、`addType`/`addProto`/`addField`/`addMethod` 追加过条目、`addProtoWithParams` 用过自有参数表）返回 `NotIncremental`，调用方应改走 canonical。`classDefs` 允许 erase（类删除）；手工改写 ID 表字段值是调用方违约，产物未定义。

- **发现**：从 DOM 引用图出发枚举全部源条目（含共享去重），再对六类自描述段（type_list、annotation set/ref list、annotation_item、encoded_array、debug_info）按 map 声明的段范围逐项走查补齐——工具会发射无人引用的孤儿条目（如 d8 为无注解类生成的空 annotation_set_item），漏掉它们会改变 map 计数与 checksum；条目间按 kind 对齐（如 type_list 的 4 字节），段尾对齐 padding 交给 gap。按源偏移排序；条目之间的空隙作为 gap 原样保留——canonical 会丢弃的「不可达条目」与未知填充，增量模式不丢。
- **发射集合**：编辑后引用图仍可达的条目。被编辑断开引用的源条目删除（成员删除后无人引用的 code_item、类删除、`stripDebugInfo`/`stripAnnotations`、注解清空后的孤儿 set）。
- **透传判定**：未被编辑且内部引用的偏移映射不变的条目按源字节透传，不解码内容、不重编码。string_data、debug_info、指令区、annotation_item、encoded_array 与三张纯索引 ID 表天然没有偏移引用，永远透传（除非删除）；含偏移引用的定长条目（string_ids、proto_ids、class_defs、call_site_ids、注解 set/ref_list/directory、code_item 的 debug_info_off）按新映射重发射；class_data 的 code_off 是 ULEB 变长，偏移变化触发重编码。
- **布局**：条目与 gap 按源偏移顺序线性平移；新条目（替换方法体、注入方法体、自有 type_list、注解覆盖、物化静态初值）追加在同类源条目之后，无同类时落在 map_list 之前；4 对齐条目在前导 gap 尾补零。ULEB 宽度随偏移变化会再次改变 class_data 大小，布局迭代至多 4 轮求固定点，不收敛返回 `Unencodable`。
- **map_list 与 header**：map_list 按源条目顺序重发射，size/offset 更新，无条目的 section 删条目、新 section 按 type 值插入；header 透传源字节后回填变化字段（file_size、map_off、表偏移、data_off/data_size）并重算 checksum/SHA-1。
- **固定点**：无编辑的增量重建逐字节返回源文件（源自身 checksum/signature 一致时）；有编辑时二次增量稳定。
- 索引不动，因此未建模 section 的保留不再与索引重排冲突；section 整体平移，内部绝对偏移不回填，与 canonical 透传语义相同。

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

### ReadError 逐码语义（M5 分类学收口）

错误码分四档，判定「读入被拒 / 带病可读 / 延迟到访问 / 构建期」：

| 码 | 档 | 语义 | 测试背书 |
|---|---|---|---|
| `Truncated` | 硬拒 | 字节不够读完一个结构（header/表项中间截断） | malformed |
| `BadMagic` | 硬拒 | magic 不是 `dex\nNNN\0` | malformed |
| `UnsupportedVersion` | 硬拒 | 版本号不在 035–041 之列 | malformed |
| `BadHeaderSize` | 硬拒/降级 | `< 0x70` 硬拒；`!=` 版本约定（041 应为 0x78）记诊断 | malformed |
| `BadEndianTag` | 硬拒 | endian_tag 不是 0x12345678（大端变体不支持） | malformed |
| `BadFileSize` | 降级 | header.file_size 与实际字节数不符 | real_corpus |
| `BadMapList` | 降级/硬拒 | map_list 越界或与头部表计数不符（偏移越界可恢复） | malformed |
| `BadTableSpan` | 硬拒 | ID 表/区间声明的 (size, off) 越出文件 | malformed |
| `BadStringData` | 访问时 | string_data_item 越界、无终止 NUL 或 ULEB 非法（`string()`/`stringData()` 时报） | lazy |
| `BadLeb128` | 访问时 | LEB128 超过 32 位或字节数超限 | leb128 |
| `BadClassData` | 访问时/硬拒 | 偏移悬垂降级；payload 计数/差分非法则 fail-closed | malformed/lazy |
| `BadCodeItem` | 访问时 | code_item 头部、指令区或 tries 区越界/自相矛盾 | code_item |
| `BadEncodedValue` | 访问时 | encoded_value 类型、value_arg 或嵌套深度非法 | encoded_value |
| `BadIndex` | 降级 | 索引悬垂或指向错误类型的条目（解码条目时记诊断） | code_item |
| `BadChecksum` | 降级 | adler32 不符（可 `verifyIntegrity(false)` 关闭） | malformed |
| `BadSignature` | 降级 | SHA-1 签名不符（同上） | malformed |
| `IdTableFull` | 构建期 | type/proto/field/method 表达到 65536 条上限（格式硬顶） | builder |

### WriteError 逐码语义

| 码 | 语义 | 测试背书 |
|---|---|---|
| `MissingSource` | 需要源字节但模型未保留（无源走增量/透传） | incremental |
| `Unencodable` | 模型内容超出编码域宽或自相矛盾，拒绝产出截断字节 | class_data |
| `NotModeled` | 版本或结构没有冻结语义（增量路径的 041、非空 link 区、大端） | version041 |
| `SourceUnreadable` | 重建需要再次解码源条目，但源字节不可读或自相矛盾 | builder |
| `InvalidModel` | 模型引用缺失或替换项指向不存在/无方法体的方法 | builder_edit |
| `UnmappedRawSection` | 表索引需要重排，但未建模 section 无法迁移内部引用 | builder |
| `NotIncremental` | 增量重建的前提被破坏（编辑触及 ID 表），需改走 canonical | incremental |

### 帧分析诊断（FrameDiagnostic，strict 档）

`WidePairing`（cat2 半寄存器被独立读写）、`MoveResultPair`（move-result 未紧跟
invoke/filled-new-array）、`MonitorBalance`（出口深度非零 / exit 无配对）、
`TypeConflict`（冲突合流的寄存器被读取——合并本身静默，与 ART 的延迟判废
一致）、`BadOperand`（寄存器越界 / 引用种类不符 / 参数个数不符）。best-effort
档同一引擎、零诊断；语料门要求真实 dex 全方法 strict 零诊断（analysis_test）。

## 指令

`decodeInsns` 覆盖 26 种定长格式与三类 payload，给出地址、宽度、寄存器、索引、立即数与分支偏移；未定义操作码返回错误。

`encodeInsn`/`encodeInsns` 按 opcode 的定长格式写回，域宽溢出返回 `OperandOverflow`，payload 错位返回 `MisalignedPayload`。不自动插 nop、不改变形态。

库还给 adapter 提供编辑原语：`constFormFits`、`insnIndexLimit`、`insnBranchTarget`/`setInsnBranchTarget`、`recomputeInsnAddresses`，寄存器域的 `insnRegisterLayout`/`insnRegisterAt`/`setInsnRegister`/`setInsnRegisterRange`/`insnRegisterCeiling` 与批量 `shiftInsnRegisters`/`remapInsnRegisters`，以及 payload 构造器 `makePackedSwitchPayload`/`makeSparseSwitchPayload`/`makeFillArrayDataPayload`（返回自包含的 `PayloadInsn`，storage 移动不失效）。寄存器写入按格式域宽校验（4/8/16 位）；重映射对 range 格式要求映射在区间上是平移，不平移的重排需要改成 35c 形态，归 adapter。sparse 构造器要求 key 严格递增（ART 按二分查找解释）。payload 标识取规范值 0x0100/0x0200/0x0300——0x0101 是 `move vA,vB` 的合法编码，不能当 packed-switch 标识（此前版本曾写反，真实语料的 move 指令被误判 payload 而报错）。label、CFG 与 const 形态选择仍归 adapter。

payload 不展开成 target 数组，保留源字节视图；switch target 相对 switch 指令地址。

## 类型与容器

type 层只解析字段类型与方法描述符，不查 ID 表、不解析泛型签名。

单文件职责；classes2.dex、APK 容器、resources.arsc 与 AXML 都在库外。

## 对拍

文本 oracle 是 baksmali 2.5.2（dexlib2）：原文件与 `buildDex` 产物分别反汇编，smali 文本必须一致。canonical 重建按规范重排 method_ids 后，class_data 的方法顺序会变；方法块顺序不是语义，脚本按块排序后再 diff，字段、注解与指令文本仍逐字节比较。它覆盖指令、try/catch、注解、静态初值、debug 行号与访问标志。

baksmali 不覆盖未建模 section，也不等于 ART 接受。仲裁规则（ART 终审、规范裁决工具分歧、环境缺席明确 skip）见 [tools/oracle/README.md](../tools/oracle/README.md)；`check.sh` 按 `LIBDEX_ORACLE_MODE` 分派 baksmali/redex/art 三种模式，redex 与 art 在对应工具缺席时明确 skip。

redex 模式是双边管线对比：原文与重建产物走同一 ReDex 优化管线，管线自身的改写（内联、DCE 等）对两侧等价生效而抵消，两侧产物反汇编后必须一致——单边对比会被管线自身改写污染。CI（Linux）用 Homebrew bottle 装 redex，并用 runner 预装 Android SDK 的 d8 生成语料跑 baksmali/redex 对拍；art 的常驻设备配方见 oracle README。

真实语料不入库，通过 `LIBDEX_REAL_DEX_DIR` 注入；第三方 APK 只允许哈希清单与复现脚本。040/041 由设备提取（`tools/corpus/extract_art.sh`），container 语义的评估与待决问题见 [corpus_040_041_notes](corpus_040_041_notes.md)。

## 不做

- odex / vdex / art / compact dex。
- APK、resources.arsc、AXML 与多 dex 模型。
- ID 表条目新增与删除（字符串 intern 除外）；压缩与 vacuum 仅作为 canonical 路径的显式 opt-in（`BuildOptions::vacuumIds`）。
- visitor 形状；方法体 AST 已翻案为 CodeDom（值句柄、无 visitor，见「分层」）。
- opcode 形态合并或自动提升（core；libsmali 汇编器作为 adapter 显式选形态）。
- 修改后字节 diff 最小化：增量重建保留源布局，输出 diff 小是布局保持的结果而非优化目标；库不提供字节级 patch。

## 相关

- [README](../README.md)：构建与最小示例。
- [dev_plan](../dev_plan.md)：实现进度与下一步。
