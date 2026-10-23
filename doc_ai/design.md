# libdex 设计真源

状态：开发中，未发布（2026-10-23）。仓内尚无首个提交，也没有外部 oracle 对拍；当前实现只算原型切片。本文是 libdex 的契约与裁决记录，前身是 morpher 工作区的 libjdex 立项草案；实现仓取 libdex，与 libjbc 同字数，契约同族。

## 1 定位

libdex 是 DEX 字节核（L1），与 libjbc core（JVM 字节核）平行同层。输入单个 `.dex` 字节（版本 035–041），输出字节核 DOM 与保真写回字节；DIR（L3 前端 IR）与 APK 容器链消费它。

所有权单位是单 DexFile，不是 APK，也不是多 dex 集合。header、map_list、五张全局 ID 表、class_defs 与全部 lazy 解码产物由这一个对象拥有，析构一次回收。

上游输入是文件系统或容器层（libjzip 的 APK 面）交出的单个 dex 字节；下游是 DIR builder 与 smali 文本层（下一阶段）。

## 2 契约

### 2.1 所有权与生命周期

一个 DexFile 拥有源字节、骨架与全部懒解码产物。公共 API 不产生调用方必须 delete 的裸指针；类身份绑定 type 索引（稳定），class_defs 的位置序只是编码细节。

零拷贝视图（MUTF-8 字节、type_list、code insns）一律指向模型自有源字节。reader 默认把入参复制进模型；关闭复制时借用调用方 buffer，调用方必须在模型存活期内保证其有效。

### 2.2 eager/lazy 划线

eager：header 全字段、map_list、五张 ID 表的定长条目、class_defs。这部分代价只与表大小相关，与类体规模无关。

lazy：string_data_item、class_data_item、code_item、type_list。debug_info、annotations、encoded_array 当前只保留偏移，Content 留待消费方需要时再解码。

解码结果缓存；`peek` 不解码也不置脏；解码失败的结果同样缓存，重复调用返回同一个错误。

### 2.3 保真与完整性

未修改写回原字节透传，连 header 的 checksum/signature 都不重算。原文件校验字段本就错误时，往返产物保留错误并出诊断——写回不是 sanitizer。修改后的写回裁决是「全量重写单一 canonical 布局」；只读核没有修改入口。

读取时可选核对两项完整性：checksum 为 adler32，覆盖 offset 12 起的字节；signature 为 SHA-1，覆盖 offset 32 起的字节。核对失败只降级为 `Recovered`，不拒绝读取。

现实语料存在「checksum 已更新、SHA-1 过期」的产物，本地两份真实 dex 都是这种形态（被工具改过正文后只重算 checksum）。因此两项核对默认开启但不拦读取；需要干净模型的调用方可以关闭核对，或按诊断过滤。`BadSignature` 不单独构成拒绝理由。

### 2.4 全局 ID 表

五张 ID 表（string/type/proto/field/method）只追加、永不重编号。理由与 libjbc 的常量池只追加裁决同构：注解、debug_info、encoded_value 等结构内嵌的是索引值，只有索引稳定，保真才不依赖对未知数据的语义猜测。

追加次序是先 string 后引用方：type 依赖描述符 string，proto 依赖 shorty string 与返回/参数 type，field/method 依赖声明类、名字与类型。intern 语义为内容去重，命中既有条目返回原索引，miss 才分配新索引。

class_defs 是载荷表，可以删除与重排；删类只在五表留下不可回收的垃圾条目，不 vacuum。类身份用 class_idx（type 索引），不用 class_defs 位置序。

容量上限：type/proto/field/method 各 65536 条；string 是 u32 域，const-string 的 16 位引用超出后必须走 `const-string/jumbo`，编码职责在 DIR。只读核目前不提供追加入口，护栏随编辑写回阶段落地。

### 2.5 错误与状态

错误走 Result 值语义，不抛异常。结构性错误（无法确定后续边界：magic、版本、表区间、map 定位、class_data/code_item 内部越界）返回 Err，不产出半截模型。

语义性错误（校验和不符、悬垂索引、map 计数与头部不符）记诊断并把 `ParseState` 置 `Recovered`，模型照常可读、可原样写回。诊断是解析产物的一部分，不是 stderr 副作用。

`ParseState` 只有两态：`Validated` 与 `Recovered`。libjdex 草案里的 `RawOnly`（不可划分结构但允许受限 patch）在只读核中不出现；结构损坏一律 Err。大端 `endian_tag` 当前直接 Err，`RawOnly` 等真实需求出现再议。

错误码与诊断定义在 `src/dex/core/error.hpp`；诊断带源字节偏移，供回溯定位。

### 2.6 指令层

code_item 的目录仍由 DexFile 懒解码；insns 区的指令流是独立接口 `decodeInsns(ByteSlice)`，返回按地址排序的 `Insn` 数组。操作码元数据覆盖 0x00–0xff，其中 224 个已定义；未定义槽返回 `format=Unknown` 的条目，查询不抛异常。

`Insn` 只保存形状事实：地址、宽度、格式、寄存器操作数、索引、立即数与分支偏移。索引按 `IndexKind` 区分 string/type/field/method/proto/call-site/method-handle；21h 的立即数已按 opcode 左移 16 或 48 位；35c/45cc 的寄存器按调用参数顺序填入，3rc/4rcc 用起始寄存器加计数表示。

三层 payload（packed-switch / sparse-switch / fill-array-data）不展开成 target 数组，而是保留指向源字节的零拷贝视图，并提供按索引取 key/target 的访问器。payload 必须落在偶数 code unit 地址；switch 的 case target 是相对 switch 指令地址的偏移，不是相对 payload。指令流接口不持有源字节，视图有效期与入参 `ByteSlice` 一致。

未定义操作码、指令中途截断与自相矛盾的 payload 返回 `InsnError`（Truncated / UnknownOpcode / BadPayload），不产出半截指令流。低字节为 0、高字节非 payload 标识的 code unit 按 ART 的宽容度当作 nop，避免个别混淆产物因 `nop` 变体被整体拒绝。

### 2.7 类型层与 IR 层

type 层只做描述符语法：字段类型、方法参数与返回、类内部名边界、数组维数与 255 维上限。解析结果借用输入串，不查 ID 表、不做泛型签名；`V` 只允许出现在方法返回位。访问标志与泛型签名后置。

ir 层的 CodeDom 是方法级只读视图：按地址排序的指令、label 集合、展平的 try 区域与结构问题列表。CodeDom 持有源字节的共享所有权（libca `Bytes` 引用计数），所以 payload 视图在 DexFile 析构后仍有效。label 由分支目标、switch case、payload 与 try 边界推导，去重排序；目标越界、落在 payload 中间、payload 种类不符、try 边界非指令等事实进入 issues，不阻断构建。try 的 typed catch 与 catch-all 展平成多条区域，catch-all 的 type 索引为 -1。

### 2.8 容器与多 dex

DexFile 恒为单文件职责。classes.dex / classes2.dex 的枚举与字节进出归容器层；主 dex 64K 与多 dex 分布是容器层及以上决策，字节核只提供单文件内的容量事实。

跨文件引用经运行时语义连接，跨 dex 分析与全局索引归 mbase。resources.arsc / AXML 不解析不编辑，容器层原样透传；odex / vdex / art 不在范围。

## 3 当前实现（未发布）

版本：035 / 037 / 038 / 039 / 040 / 041。041 的 `container_size` / `header_offset` 扩展在 `header_size ≥ 0x78` 时读取，缺少时降级记录；当前没有真实 041 语料，字段语义待 oracle 实测冻结。

解析：header、map_list、五张 ID 表、class_defs eager；string_data、class_data、code_item、type_list lazy。表区间越界是 Err；跨表索引悬垂与 map 计数不符是诊断。

访问面：类/父类/来源文件描述符，字段与方法的名字、owner、类型，原型参数与类接口列表，class_data 目录，code_item 头部、insns/tries span、try 与 encoded_catch_handler。

指令：0x00–0xff 操作码表、26 种定长编码格式与 3 类 payload 的形状解码；逐条给出寄存器、索引、立即数与分支偏移。合成用例覆盖全部格式与三类 payload 的边界；真实语料的每个方法体都解码并核对「宽度和 = insns_size」、31t 引用的 payload 类型与 switch case 目标落在指令边界。

类型与 IR：字段/方法描述符解析（类名、数组维数、V 的位置）；CodeDom 给出指令、label、展平的 try 区域与结构问题，真实语料的每个方法体都构建成功且 issues 为空。

写回：未修改原字节透传；无源字节返回 `MissingSource`。

测试：57 个用例，真实语料门控的 2 个在有语料时执行。合成 035 fixture 覆盖骨架解析、懒解码、指令解码、try/handler、描述符、CodeDom、畸形输入、完整性已知向量与字节级往返；本地两份真实语料（5.5 KB 与 719 KB）通过解析、往返、全方法体指令解码与 CodeDom 构建。

明确未落地：注解/encoded_value、静态初值、debug_info、call site/method handle、修改入口、指令编码器、builder/canonical 写回、smali 文本层、APK 容器语义、dexlib2/baksmali/ReDex 对拍器。MUTF-8 只给字节视图，不做码点校验或转码；type_list 只给视图，不校验元素索引。

## 4 阶段与判据

只读核（自证通过，未接 oracle）：解析、未修改往返。判据是真实语料字节一致、结构计数与 oracle 对拍一致、畸形样本 fail-closed。

DIR builder：DexFile → DIR builder + writer。指令形状矩阵已由 insn 层提供；判据是 DIR 深比较往返、offset 与 index 映射精确、baksmali 文本对拍（指令序列语义一致）。

编辑写回与 smali 文本层：修改路径（全量重写 + checksum/signature 重算），smali 文本层作为独立新库（语法对齐 baksmali，不绑定其格式细节）。判据是 libjbc 同族编辑任务集写回后 baksmali 对拍一致，ID 表只追加不变量有门禁单测。

APK 容器语义：段对齐、APK Signing Block、签名重签。先按 v2/v3 公开规范自实现，再评估壳调 apksigner 的合规路径；产物以 apksigner verify 对拍。

## 5 复用资产

libjstr：MUTF-8 视图与容器直接复用；DexFile 的字符串视图指向模型自有源字节，不额外复制。

libca：`Result`、定长类型、UTF-8 字符串与加密。源字节所有权用 `ca::core::Bytes`（自有 `copy_from_slice` 或借用 `from_static`），非拥有视图用 `ByteSlice`，重编码写回用 `BytesMut`。小端读取全部走 `Bytes::get_u16_le`/`get_u32_le`；libdex 只保留一个薄 `Reader`：在任意 offset 处切一个共享存储的 `Bytes` 视图并把 `BytesError` 映射成 `ReadError`。libca 的 `Bytes` 不能从当前游标跳转、`slice()` 越界抛异常，DEX 又是 offset 驱动的不可信输入，所以“切视图 + Result 错误”这一层不能省，端序位移则不再手写。SHA-1 复用 libca crypto；adler32 在 libdex 自持，因为 libca crypto 只提供 CRC16/CRC32 与哈希族，没有 adler32。

LEB128：读取面 libdex 自持。libca 的 `get_var_u32` 只接受最小编码，冗余填充报 `MalformedVarint`；DEX 读取面按 ART 的宽容度接受非最小编码，避免混淆产物被误拒。写入端后续直接用 libca 的 `put_var_u32` 产出最小编码，不需要另写一套。libjblw 内的实现不是公共设施，等它退役后再评估归位。

libjzip：APK 容器底座，容器阶段才需要；当前不依赖。

## 6 oracle 与语料

语义真源是 dexlib2，文本真源是 baksmali/smali，写回参照是 ReDex。对拍方法沿用 libjzip 的 run_crossval 先例；三 oracle 不一致时以 AOSP DEX 格式规范为最终仲裁。

只读核当前以真实 dex 的字节级往返与结构自洽自证，oracle 对拍器尚未接线。真实语料不入库，经 `LIBDEX_REAL_DEX_DIR` 注入；第三方 APK 本体不提交，只允许哈希清单与复现脚本入库。

合成 fixture 覆盖结构路径与边界；真实语料覆盖工具链产物与现实畸形容错。语料缺席时对应测试 skip，不硬失败。

## 7 明确不做

- 不做 odex / vdex / art 镜像格式。
- 不做 compact dex 原生读写；标准 dex 与 cdex 互转后置。
- 不做 resources.arsc / AXML 的解析与编辑。
- 不做多 dex 集合模型，不持有 APK。
- 不做五表重编号、压缩与 vacuum。
- 不做 visitor 形状；模型是数据，不提供回调推送。
- 不做全局 Context 与跨文件共享 arena。
- 不承诺修改后输出字节 diff 最小。
- 不做行为级语义验证；桌面无 ART，语义回归由 oracle 对拍承担。
- 不承诺与 baksmali 文本格式逐字节兼容。

## 8 相关文档

- [README](../README.md)：构建、最小示例与语料入口。
- [dev_plan](../dev_plan.md)：落地账目与下一批工作。
- morpher 工作区的 libjdex 立项草案（`morpher-docs/libs/libjdex/doc_ai/design.md`）是本文前身；契约条款与待裁决问题同源，本仓以 libdex 名落地。
