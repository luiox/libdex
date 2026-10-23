# libdex 设计真源

状态：开发中，未发布（2026-10-23）。仓内只有原型基线提交，还没有外部 oracle 对拍；当前实现只算原型切片。本文是 libdex 的契约与裁决记录，前身是 morpher 工作区的 libjdex 立项草案；实现仓取 libdex，与 libjbc 同字数，契约同族。

## 1 定位

libdex 是 DEX 字节核（L1），与 libjbc core（JVM 字节核）平行同层。输入单个 `.dex` 字节（版本 035–041），输出字节核 DOM 与保真写回字节；DIR（L3 前端 IR）与 APK 容器链消费它。

所有权单位是单 DexFile，不是 APK，也不是多 dex 集合。header、map_list、五张全局 ID 表、class_defs 与全部 lazy 解码产物由这一个对象拥有，析构一次回收。

上游输入是文件系统或容器层（libjzip 的 APK 面）交出的单个 dex 字节；下游是使用方的 adapter 与 smali 文本层。

### 1.1 分层：保真 DOM / codec / adapter

库只做两层：保真 DOM（core/insn）与逐条目 codec（解码 + 精确编码）。库不定义方法体或类的高层 AST，也不提供 label、CFG、try 展平这类语义视图。

需要简化语义时，使用方在自己的 adapter 里把 DOM 映射成自选 AST。例如把 `const/4`、`const/16`、`const`、`const/high16` 合并成单个 `iconst x`；写回时由 adapter 按取值域选择具体 opcode，库只按选定的 opcode 精确编码，绝不替调用方做形态提升或合并。不同需求对应不同 AST，库不绑定其中任何一种。

分层理由：AST 的简化方向由使用场景决定（反混淆、审计、重写、文本化各不相同），任何库内 AST 都会在某些场景下丢失必要细节；保真层则对所有场景相同，且可以逐字节验证。代价是库不提供「一键可编辑树」，换取保真面不被简化视图污染。

## 2 契约

### 2.1 所有权与生命周期

一个 DexFile 拥有源字节、骨架与全部懒解码产物。公共 API 不产生调用方必须 delete 的裸指针；类身份绑定 type 索引（稳定），class_defs 的位置序只是编码细节。

零拷贝视图（MUTF-8 字节、type_list、code insns）一律指向模型自有源字节。reader 默认把入参复制进模型；关闭复制时借用调用方 buffer，调用方必须在模型存活期内保证其有效。

### 2.2 eager/lazy 划线

eager：header 全字段、map_list、五张 ID 表的定长条目、class_defs。这部分代价只与表大小相关，与类体规模无关。

lazy：string_data_item、class_data_item、code_item、type_list、注解族（annotation_item / annotation_set_item / annotation_set_ref_list / annotations_directory_item）、encoded_array_item 与 debug_info_item。call_site_id 与 method_handle 是定长表，随骨架从 map_list 读取；map_list 中未建模的 section 记入 `rawSections`，按原始区间保留。

解码结果缓存；`peek` 不解码也不置脏；解码失败的结果同样缓存，重复调用返回同一个错误。注解族与 debug_info 按文件偏移缓存，同一 set/item 被多个类或参数共享时只解一次。

### 2.3 保真与完整性

未修改写回原字节透传，连 header 的 checksum/signature 都不重算。原文件校验字段本就错误时，往返产物保留错误并出诊断——写回不是 sanitizer。需要修改内容或重排布局时走 `buildDex`：它是「全量重写单一 canonical 布局」的唯一路径，从可达条目重新生成整份文件。

`buildDex` 的布局顺序是 header、五张 ID 表、class_defs、call_site_ids、method_handles，数据区依次为 string_data、type_list、encoded_array、annotation_item、annotation_set、annotation_set_ref_list、annotations_directory、debug_info、code_item、class_data、未建模 section、map_list。string_data 与 type_list 原字节复制，class_data、code_item、debug_info、注解容器按新偏移重编码，所有内嵌文件偏移回填，map_list 重建，checksum/signature 重算。只输出从 header、五张 ID 表、class_defs 与 call_site_id 可达的条目，不可达的建模条目被丢弃；未建模 section 按原字节透传，其中若含绝对偏移不会回填。版本 041 与非空 link 区语义未冻结，返回 `NotModeled`；重建期间再次解码失败返回 `SourceUnreadable`，替换项不合法返回 `InvalidModel`。

保真沿用 libjbc 的三条机制：数据条目记录源区间（`ByteSpan raw`）、lazy 解码结果挂缓存、未建模区段不猜语义。注解族、encoded_array_item 与 debug_info_item 的 raw 区间覆盖条目从起始到解码结束的完整字节；`encoded_value` 保留原始 `value_arg`（载荷宽度），不按最小值归一化，因此解码后再编码可以逐字节还原源编码。map_list 中未知类型的 section 不会被丢弃：`rawSections` 记录类型、声明条目数与源区间（长度含对齐填充）。真实语料的每个静态初值数组、每个 annotation_item、每个 class_data_item、每个 code_item 与每个方法体都在测试里做解码→重编码字节比较，作为保真的硬门禁。

读取时可选核对两项完整性：checksum 为 adler32，覆盖 offset 12 起的字节；signature 为 SHA-1，覆盖 offset 32 起的字节。核对失败只降级为 `Recovered`，不拒绝读取。

现实语料存在「checksum 已更新、SHA-1 过期」的产物，本地两份真实 dex 都是这种形态（被工具改过正文后只重算 checksum）。因此两项核对默认开启但不拦读取；需要干净模型的调用方可以关闭核对，或按诊断过滤。`BadSignature` 不单独构成拒绝理由。

### 2.4 全局 ID 表

五张 ID 表（string/type/proto/field/method）只追加、永不重编号。理由与 libjbc 的常量池只追加裁决同构：注解、debug_info、encoded_value 等结构内嵌的是索引值，只有索引稳定，保真才不依赖对未知数据的语义猜测。

追加次序是先 string 后引用方：type 依赖描述符 string，proto 依赖 shorty string 与返回/参数 type，field/method 依赖声明类、名字与类型。intern 语义为内容去重，命中既有条目返回原索引，miss 才分配新索引。

class_defs 是载荷表，可以删除与重排；删类只在五表留下不可回收的垃圾条目，不 vacuum。类身份用 class_idx（type 索引），不用 class_defs 位置序。

容量上限：type/proto/field/method 各 65536 条；string 是 u32 域，const-string 的 16 位引用超出后必须走 `const-string/jumbo`，编码职责在 adapter。只读核目前不提供追加入口，护栏随编辑写回阶段落地。

call_site_id 与 method_handle 没有头部计数，只由 map_list 定位；两者是定长表，骨架期直接读出。method_handle 的两个 unused 字段原样保留，不按规范值清零。map_list 中未建模类型的 section 进入 `rawSections`，记录原始 type 值、声明条目数与源区间，写回按原字节透传。

### 2.5 错误与状态

错误走 Result 值语义，不抛异常。结构性错误（无法确定后续边界：magic、版本、表区间、map 定位、class_data/code_item 内部越界）返回 Err，不产出半截模型。

语义性错误（校验和不符、悬垂索引、map 计数与头部不符）记诊断并把 `ParseState` 置 `Recovered`，模型照常可读、可原样写回。诊断是解析产物的一部分，不是 stderr 副作用。

`ParseState` 只有两态：`Validated` 与 `Recovered`。libjdex 草案里的 `RawOnly`（不可划分结构但允许受限 patch）在只读核中不出现；结构损坏一律 Err。大端 `endian_tag` 当前直接 Err，`RawOnly` 等真实需求出现再议。

错误码与诊断定义在 `src/dex/core/error.hpp`；诊断带源字节偏移，供回溯定位。

### 2.6 指令层

code_item 的目录仍由 DexFile 懒解码；insns 区的指令流是独立接口 `decodeInsns(ByteSlice)`，返回按地址排序的 `Insn` 数组。操作码元数据覆盖 0x00–0xff，其中 224 个已定义；未定义槽返回 `format=Unknown` 的条目，查询不抛异常。

`Insn` 只保存形状事实：地址、宽度、格式、寄存器操作数、索引、立即数、分支偏移与原始 code unit 视图 `raw`。索引按 `IndexKind` 区分 string/type/field/method/proto/call-site/method-handle；21h 的立即数已按 opcode 左移 16 或 48 位；35c/45cc 的 unit0 按 `A|G|op` 拆开（A 是高 nibble 的参数个数，G 是 bits 11..8 的第五个寄存器），3rc/4rcc 用起始寄存器加计数表示。

编码面是逐 opcode 的定长写入：`encodeInsn` 只按 `Insn::format` 对应的格式占位，不改变 opcode、不做 `const/4 → const/16` 之类的形态提升，字段超出该格式域宽返回 `OperandOverflow`；`encodeInsns` 逐条拼接并检查 payload 的偶数 code unit 地址，落在奇地址返回 `MisalignedPayload`，不自动插入 nop。10x/20t/30t/32x 的未用高位与 fill-array-data 的补齐字节在 `raw` 与当前指令一致时原样沿用，因此解码→编码逐字节一致。形态选择（例如给某个整数值选哪一种 const）是 adapter 的职责，库只提供各形态的域宽与编码器。

三层 payload（packed-switch / sparse-switch / fill-array-data）不展开成 target 数组，而是保留指向源字节的零拷贝视图，并提供按索引取 key/target 的访问器。payload 必须落在偶数 code unit 地址；switch 的 case target 是相对 switch 指令地址的偏移，不是相对 payload。指令流接口不持有源字节，视图有效期与入参 `ByteSlice` 一致。

未定义操作码、指令中途截断与自相矛盾的 payload 返回 `InsnError`（Truncated / UnknownOpcode / BadPayload），不产出半截指令流。低字节为 0、高字节非 payload 标识的 code unit 按 ART 的宽容度当作 nop，避免个别混淆产物因 `nop` 变体被整体拒绝。

### 2.7 类型层

type 层只做描述符语法：字段类型、方法参数与返回、类内部名边界、数组维数与 255 维上限。解析结果借用输入串，不查 ID 表、不做泛型签名；`V` 只允许出现在方法返回位。访问标志与泛型签名后置。

debug_info 是寄存器/行号状态机的字节码。模型按操作码保留原始字节（special 区间不归一化）与解码后的操作数，`raw` 覆盖 line_start 到 END_SEQUENCE；写回按操作码重写操作数并自动补 END_SEQUENCE，special 的 addressDiff/lineDiff 必须与 opcode 自洽。这里不做行/局部变量的语义推导，只保留状态机条目。

库不提供方法体 CodeDom、label、CFG 或 try 展平。`CodeItem` 保留 try_item 与 encoded_catch_handler 的原始结构（共享的 handler 不被复制展平），分支目标保持相对偏移；需要标签或控制流图的调用方在自己的 adapter 里构建，并自行承担插入/删除后的偏移重算。

### 2.8 容器与多 dex

DexFile 恒为单文件职责。classes.dex / classes2.dex 的枚举与字节进出归容器层；主 dex 64K 与多 dex 分布是容器层及以上决策，字节核只提供单文件内的容量事实。

跨文件引用经运行时语义连接，跨 dex 分析与全局索引归 mbase。resources.arsc / AXML 不解析不编辑，容器层原样透传；odex / vdex / art 不在范围。

## 3 当前实现（未发布）

版本：035 / 037 / 038 / 039 / 040 / 041。041 的 `container_size` / `header_offset` 扩展在 `header_size ≥ 0x78` 时读取，缺少时降级记录；当前没有真实 041 语料，字段语义待 oracle 实测冻结。

解析：header、map_list、五张 ID 表、class_defs、call_site_id、method_handle eager；string_data、class_data、code_item、type_list、注解族、encoded_array_item 与 debug_info lazy。表区间越界是 Err；跨表索引悬垂与 map 计数不符是诊断。map_list 中未知类型的 section 进入 `rawSections`，不丢弃。

访问面：类/父类/来源文件描述符，字段与方法的名字、owner、类型，原型参数与类接口列表，class_data 目录，code_item 头部、insns/tries span、try 与 encoded_catch_handler，注解目录/set/ref list/item、静态初值数组、call_site 值、method_handle 表与 debug_info。

值编码：encoded_value 全 18 种类型码、value_arg 原始宽度、数组/注解递归、深度上限；`writeEncodedValue`/`writeEncodedArray`/`writeEncodedAnnotation` 按所记宽度重编码，超宽或自相矛盾返回 `Unencodable`，不静默截断。注解容器（annotation_item、set、ref list、directory、encoded_array_item）各有 item writer，整条目解码→编码字节一致。debug_info 有状态机条目模型与 `writeDebugInfo`；解码产生的 header 与每条操作保留原始字节（包括非最小 ULEB/SLEB），修改时清空对应 raw 才按字段重编码。

结构写回：`writeClassData` 由绝对索引重新计算差分，索引非严格递增时拒绝；`writeCodeItem` 按 `TryBlock::handlerIndex` 重算 handler_off，共享的 handler 保持共享，奇数 insns 在 tries 前补 2 字节。真实语料的每个 class_data_item 与 code_item 都做整条目解码→编码字节比较。

整文件重建：`buildDex(DexFile&, const BuildOptions&)` 按上一节的 canonical 顺序重新生成文件，回填 header 的 ID 表偏移、proto 的 parameters_off、class_defs 的 interfaces/annotations/class_data/static_values、call_site 的 call_site_off、code_item 的 debug_info_off 与 class_data 的 code_off，并重建 map_list 与完整性字段。`CodeReplacement` 按 method_idx 替换方法体：调用方给出编码后的 insns 与 CodeItem 头部/tries，`debugInfoOff` 解释为源文件偏移并重映射；同一 code_item 被多个方法共享时，未替换的方法继续指向原条目，被替换的方法单独产出条目。debug_info/注解/数组按旧偏移去重，共享关系保持。重建会按需解码条目并填充 lazy 缓存，所以入参是非 const 引用，但语义上不修改文件内容。

指令：0x00–0xff 操作码表、26 种定长编码格式与 3 类 payload 的形状解码；逐条给出寄存器、索引、立即数、分支偏移与原始 code unit 视图 `raw`。编码面按 opcode 的定长格式逐位写回，支持全部 26 种格式与三类 payload；35c/45cc 的 A/G nibble 已按 `A|G|op` 修正。合成用例覆盖全部格式与三类 payload 的边界；真实语料的每个方法体都解码后逐字节重编码比对，并核对「宽度和 = insns_size」、31t 引用的 payload 类型与 switch case 目标落在指令边界。

类型：字段/方法描述符解析（类名、数组维数、V 的位置）。库不提供方法体 AST。

写回：未修改原字节透传；无源字节返回 `MissingSource`。`buildDex` 做 canonical 重建，失败面为 `NotModeled`（041、非空 link 区）、`SourceUnreadable`（重建时再次解码失败）、`InvalidModel`（替换项或引用缺失）与 `Unencodable`（条目超域宽）。

测试：89 个用例，真实语料门控的 4 个在有语料时执行。合成 035 fixture 覆盖骨架解析、懒解码、指令解码与编码、try/handler、描述符、注解族、值编码、debug_info（含非最小操作数编码）、call_site/method_handle、未知 map section、class_data/code_item 重编码、整文件重建与方法体替换、畸形输入、完整性已知向量与字节级往返；本地两份真实语料（5.5 KB 与 719 KB）通过解析、往返、全方法体指令的解码→编码逐字节比较、全注解目录遍历与注解条目/静态初值/class_data/code_item 的解码→重编码字节比较。整文件重建测试对两份语料重新解析为 Validated、核对完整性字段、逐方法比较指令字节、遍历新注解与静态初值偏移，并验证二次重建字节稳定。两份本地语料是 stripped 产物，不含 debug_info 与 call site，相关路径由合成 fixture 覆盖。

明确未落地：条目级 dirty 状态、ID 表追加护栏、smali 文本层、APK 容器语义、ReDex 写回参照与 ART 实机验证。MUTF-8 只给字节视图，不做码点校验或转码；type_list 只给视图，不校验元素索引；builder 只保证 canonical 输出自洽，不承诺修改后字节 diff 最小，也不推断未建模 section 内部的绝对偏移。

## 4 阶段与判据

只读核与逐条目 codec（自证通过，未接 oracle）：解析、未修改往返、指令与值编码。判据是真实语料字节一致、指令解码→编码逐字节一致、畸形样本 fail-closed。

低层写回：item writer、canonical 布局、checksum/signature 重算已落地；条目级 dirty 状态与 ID 表追加护栏待做。判据是条目级解码→编码字节一致、整文件未修改往返字节一致、修改后结构自洽、重建产物二次重建字节稳定。

adapter 与 smali 文本层：adapter 归使用方或独立仓，库只提供 DOM/codec 与布局原语；smali 文本层作为独立新库（语法对齐 baksmali，不绑定其格式细节）。判据是 adapter 写回后 baksmali 对拍一致、ID 表只追加不变量有门禁单测。

APK 容器语义：段对齐、APK Signing Block、签名重签。先按 v2/v3 公开规范自实现，再评估壳调 apksigner 的合规路径；产物以 apksigner verify 对拍。

## 5 复用资产

libjstr：MUTF-8 视图与容器直接复用；DexFile 的字符串视图指向模型自有源字节，不额外复制。

libca：`Result`、定长类型、UTF-8 字符串与加密。源字节所有权用 `ca::core::Bytes`（自有 `copy_from_slice` 或借用 `from_static`），非拥有视图用 `ByteSlice`，重编码写回用 `BytesMut`。小端读取全部走 `Bytes::get_u16_le`/`get_u32_le`；libdex 只保留一个薄 `Reader`：在任意 offset 处切一个共享存储的 `Bytes` 视图并把 `BytesError` 映射成 `ReadError`。libca 的 `Bytes` 不能从当前游标跳转、`slice()` 越界抛异常，DEX 又是 offset 驱动的不可信输入，所以“切视图 + Result 错误”这一层不能省，端序位移则不再手写。SHA-1 复用 libca crypto；adler32 在 libdex 自持，因为 libca crypto 只提供 CRC16/CRC32 与哈希族，没有 adler32。

LEB128：读取面 libdex 自持。libca 的 `get_var_u32` 只接受最小编码，冗余填充报 `MalformedVarint`；DEX 读取面按 ART 的宽容度接受非最小编码，避免混淆产物被误拒。写入端后续直接用 libca 的 `put_var_u32` 产出最小编码，不需要另写一套。libjblw 内的实现不是公共设施，等它退役后再评估归位。

libjzip：APK 容器底座，容器阶段才需要；当前不依赖。

## 6 oracle 与语料

语义真源是 dexlib2，文本真源是 baksmali/smali，写回参照是 ReDex。对拍方法沿用 libjzip 的 run_crossval 先例；三 oracle 不一致时以 AOSP DEX 格式规范为最终仲裁。

已接 baksmali 2.5.2 文本对拍：`tools/oracle/check.sh` 用 `dexbuild rebuild` 生成重建产物，再分别反汇编原文与产物，要求 smali 文本完全一致。baksmali 覆盖指令、try/catch、注解、静态初值、debug 行号与局部变量、访问标志与类层次；未建模 section 不在文本面内，由 raw 保留用例覆盖。jar 固定版本并从 Maven Central 拉取到 `.oracle-cache/`，CI 在 Ubuntu 与 Windows 上用合成 fixture 执行；本地两份真实语料（5.5 KB 与 719 KB）均通过。ReDex 写回参照与 ART 实机验证尚未接线；baksmali 通过只说明 dexlib2 能解析且语义一致，最终仲裁仍是 AOSP 规范。

真实语料不入库，经 `LIBDEX_REAL_DEX_DIR` 注入；第三方 APK 本体不提交，只允许哈希清单与复现脚本入库。

合成 fixture 覆盖结构路径与边界；真实语料覆盖工具链产物与现实畸形容错。语料缺席时对应测试 skip，不硬失败。

## 7 明确不做

- 不做 odex / vdex / art 镜像格式。
- 不做 compact dex 原生读写；标准 dex 与 cdex 互转后置。
- 不做 resources.arsc / AXML 的解析与编辑。
- 不做多 dex 集合模型，不持有 APK。
- 不做五表重编号、压缩与 vacuum。
- 不做 visitor 形状；模型是数据，不提供回调推送。
- 不提供方法体或类的高层 AST、label、CFG、try 展平；简化与语义合并归使用方 adapter。
- 不做 opcode 形态合并或自动提升（例如把 `const/4` 写成 `const/16`）；编码器只按调用方给定的形态写。
- 不做全局 Context 与跨文件共享 arena。
- 不承诺修改后输出字节 diff 最小。
- 不做行为级语义验证；桌面无 ART，语义回归由 oracle 对拍承担。
- 不承诺与 baksmali 文本格式逐字节兼容。

## 8 相关文档

- [README](../README.md)：构建、最小示例与语料入口。
- [dev_plan](../dev_plan.md)：落地账目与下一批工作。
- morpher 工作区的 libjdex 立项草案（`morpher-docs/libs/libjdex/doc_ai/design.md`）是本文前身；契约条款与待裁决问题同源，本仓以 libdex 名落地。
