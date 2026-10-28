# dev_plan

libdex 的当前能力、缺口与下一步。只记已经跑通的事实，不按版本号记账。

## 当前能力

- 解析 035–041 的 header、map_list、五张 ID 表、class_defs、call_site_id、method_handle；string_data、class_data、code_item、type_list、注解族、encoded_array、debug_info 懒解码并缓存。041 的 container 字段只读取。
- 未建模 map section 记录原始区间；未修改写回原字节透传。
- 指令层覆盖 26 种定长格式与三类 payload，按 opcode 精确编码；`Insn` 保留原始 code unit，不合并 const 形态。
- 值编码覆盖 18 种类型，保留 `value_arg`；注解族、encoded_array、debug_info 有精确 item writer。
- `writeClassData` / `writeCodeItem` 重算差分与 handler_off，保持 handler 共享；与解析器同住条目 codec 文件（class_data / code_item），条目族编解码不再落在 dex_file.cpp。
- `buildDex` 生成 canonical 布局：回填字符串、type_list、class_data、code、注解与 call_site 偏移，重建 map_list，重算 checksum/SHA-1；支持按 method_idx 替换方法体。
- `internString` / `internUtf8` 追加或复用字符串；`buildDex` 按 UTF-16 合并排序去重，重写 ID 表、const-string、debug_info、encoded_value 与注解元素名中的字符串索引。
- 类型/字段/方法改名：`buildDex` 按 DEX 排序键重排五张 ID 表与 class_defs，重新编码 type_list，重写 class_data（并按新索引重排四个列表）、注解目录、指令、catch、debug_info 局部变量、method_handle 与 encoded_value 中的全部索引。
- `addType`/`addProto`/`addField`/`addMethod` 追加或复用 ID 表条目并返回索引；表满返回 `IdTableFull`。
- 自有 type_list 池：`addTypeList` 按内容去重入池；`addProtoWithParams` 按参数列表直建 proto（shorty 自动推导 intern，与既有条目按内容去重）；`setClassInterfaces` 覆盖类接口。重建时自有列表发射为新 type_list 并回填真实偏移，owned 标志区分池下标与源偏移。
- 成员注入：`BuildOptions::fieldAdditions`/`methodAdditions` 把字段/方法写进目标类的 class_data（无 class_data 时新建），新增方法体与替换体进入统一 code 单元并参与布局。
- 新增类：追加 `classDefs` 后用成员注入填 class_data；接口可复用已有 type_list。
- 删除：类直接从 `classDefs` erase；`removedFields`/`removedMethods` 把成员移出 class_data，ID 表条目保留。
- 剥离：`stripDebugInfo` 丢弃 debug_info，`stripAnnotations` 丢弃注解族；两者都不动 ID 表与指令。
- 静态初值显式赋值：`setStaticFieldValue` 按字段覆盖初值，值类别匹配字段类型、载荷宽度归一到最小；重建替换源数组槽位或新增字段默认值，无源数组的类物化数组。
- 可写注解层：`addAnnotationItem` 把注解项按内容去重入池；`setClassAnnotations`/`setFieldAnnotations`/`setMethodAnnotations`/`setParameterAnnotations` 按成员覆盖（空集即清空）。重建把覆盖与源 annotations_directory 合并成生效目录，未覆盖成员沿用源条目，孤儿 set/ref_list 不发射；目标必须在生效 class_data 中有定义，参数个数须与 proto 一致，与 `stripAnnotations` 互斥。
- access_flags 覆盖：`fieldAccessFlags`/`methodAccessFlags` 按索引改已有成员；方法自动切换直接/虚方法分组，字段不允许改 static 位。
- 任何表索引移动与保留的未建模 section 冲突返回 `UnmappedRawSection`。
- `buildDex` 入口检查 ID 表容量与表内索引；悬垂索引、非法 method_handle 与零 call_site 返回 `InvalidModel`。
- adapter 原语：`constFormFits`、`insnIndexLimit`、`insnBranchTarget`/`setInsnBranchTarget`、`recomputeInsnAddresses`。
- adapter 原语（第二批）：寄存器域读写（`insnRegisterLayout`/`insnRegisterAt`/`setInsnRegister`/`setInsnRegisterRange`/`insnRegisterCeiling`）、批量平移与重映射（`shiftInsnRegisters`/`remapInsnRegisters`）、payload 构造器（`makePackedSwitchPayload`/`makeSparseSwitchPayload`/`makeFillArrayDataPayload`）。
- payload 标识为规范值：packed-switch 0x0100、sparse-switch 0x0200、fill-array-data 0x0300（更正：此前记录的 0x0101/0x0202 本身才是错误值——0x0101 是 `move vA,vB` 的合法编码；真实语料中 move v1,v0 被误判 payload 的回归由此修复）。
- 增量布局路径：`BuildOptions::incremental` 保留源布局，未编辑条目源字节透传，只重编码被改条目；无编辑时输出逐字节等于源。编辑不触及 ID 表，否则返回 `NotIncremental`。发现阶段按 map 段走查六类自描述段补齐孤儿条目（如 d8 的空 annotation_set_item），否则 map 计数漂移破坏字节恒等。
- 方法体 CodeDom：`CodeUnit` 槽表 + `InsnId{owner,slot,gen}` 值句柄（gen 防 ABA、跨 owner 结构性拒绝）；insert/replace/erase 双策略（引用仍在 `Err(StillUsed)` 或级联删除）；`CodeUnit ↔ decodeInsns/encodeInsns` 的 promote/lower 是唯一 code 发射通道，`buildDex` 与 incremental 共用同一 lower。
- 构建门面：`MethodEditor`（open/append/label/commit，payload 自动对齐可见 nop）；未绑定 label 的控制流按形状拒绝，失败不留半成品；`DexFile::createEmpty` + intern 家族从零构建 dex。
- vacuum（显式 opt-in `BuildOptions::vacuumIds`）：`computeVacuumClosure` 从源条目 + 编辑层根（方法体注入、CodeReplacement、注解覆盖、静态初值编辑）收集引用闭包 → 过滤式 ID 表重排 → 全引用重写（指令/debug/注解族/encoded_value/class_data/call_site/method_handle）；method_handles/call_sites 整表保留；未建模 section 在场时拒绝；二次重建字节固定。
- 分析层：`buildCfg`（leaders 切块于分支/switch 目标、try 边界、handler 入口、转移后继；流内边 + 异常边 + 前驱回填，悬垂目标不产假边）；`analyzeFrames` 不动点求逐指令入口帧——RegType 格（cat1/cat2 半寄存器配对、引用带 type_idx、UninitRef/UninitThis 由 `<init>` 调用初始化、Null 兼字面量零并入引用或 cat1 同族）；冲突合并静默进帧、被读取才报 TypeConflict（与 ART 延迟判废一致）；move-result 按 invoke/filled-new-array 配对并按返回描述符定型；invoke 参数含接收者对齐 proto；monitor 深度出口检查；best-effort 与 strict 同引擎分档。语料门：4 个真实 dex 全方法两档可解析、strict 零诊断。
- smali 反汇编（libsmali）：`disassembleClass`/`disassembleAll`，baksmali 兼容文法——类/字段/方法头、26 格式指令、label 合成（分支/payload/try/handler）、注解与静态初值、debug 投影（.source/.line/.local 族）；每类一文件。
- smali 汇编（libsmali）：`SmaliAssembler::assembleClass`，词法/递归下降、寄存器映射 pN→vN、形态选择（字面量宽度、分支距离、const-string jumbo）、label 解析、payload/try/handler/注解/初值落位；语料往返（our_disasm → our_asm → 重建）在 035–039 四语料封闭，baksmali 对拍一致；汇编程文法错误 fail-loud 不留半成品。
- 041 写回：canonical 重建解除 041 拒绝——header 0x78，container 字段按独立文件约定重置 `(file_size, 0)`；增量路径保持 `NotModeled`（实物复核前不承诺字节恒等）。
- 性能基线（dexperf）：800 类 × 80 方法（64K method_ids 格式上限内）+ 20 万字符串 ≈ 13.8 MiB——canonical 构建 1.47s、解析 88ms、全方法走查 126ms、再重建 1.21s（x64 release，2026-10-26 基准，只防回归）。
- 错误分类学：design.md 增 ReadError（17 码分硬拒/降级/访问时/构建期四档）、WriteError（7 码）与 FrameDiagnostic（5 码）逐码语义表，每码标注测试背书；ASan 门（leak_check）覆盖读→全解码→帧分析→重建→重读，含插桩自检防假绿。
- 语料矩阵：`tools/corpus/gen_corpus.sh` 用 d8 按 `--min-api 14/24/26/28` 产出 035/037/038/039 样本与 SHA-256 清单（产物不入库）；`tools/corpus/extract_art.sh` 从 root 可读设备拉取 vdex/cdex、按内嵌 magic 与段自身 file_size 切出 040/041 语料（假设备 shim 端到端验证，实物待常驻设备），说明见 doc/corpus_040_041_notes.md。
- baksmali 2.5.2 文本对拍：合成 fixture、level1（5528 B）与 level2（719560 B）在方法块顺序规范化后 diff 均为空；真实语料 035–039 的 canonical 重建与增量产物对拍通过。
- oracle 模式：`tools/oracle/check.sh` 按 `LIBDEX_ORACLE_MODE` 分派 baksmali（门槛）/redex/art（环境缺席明确 skip）；redex 是双边管线对比（原文与重建产物走同一 ReDex 管线后反汇编比较），`LIBDEX_REDEX_BIN` 可指定二进制；仲裁规则见 `tools/oracle/README.md`（ART 终审、规范裁决工具分歧）。
- CI 在 Ubuntu 与 Windows 上跑单测和 fixture 对拍；Ubuntu 另跑 d8 语料生成与语料上的 baksmali 对拍（门禁）、redex 对拍（`continue-on-error` 观察期，绿稳后转门槛）。真实语料不提交。
- 本地全量单测全绿（未设置 `LIBDEX_REAL_DEX_DIR` 时 11 个语料用例 skip）；语料上的成员/类型改名、成员增删、元数据剥离、增量-源字节恒等与二次重建固定点通过。

## 已知缺口

- 041 canonical 写回已冻结（container 重置 `(file_size,0)`），增量路径仍拒 041；实物语料到位后按 ART oracle 复核。非空 link 区同样拒绝。
- 增量路径不支持 ID 表级编辑（intern/addType/addMethod 等触发 `NotIncremental`）；跨 ID 表的大改仍走全量 canonical。
- ID 表条目不回收：删除成员/类只移除定义，索引与字符串仍占位。
- ID 表索引重排不能跨未建模 section：保留 section 时只要旧索引移动就拒绝重建。
- `buildDex` 丢弃不可达的建模条目；未建模 section 内部的绝对偏移不回填。
- 源字符串的 MUTF-8 在重建时校验 UTF-16 长度；type_list 元素索引越界返回 `InvalidModel`。
- redex 双边对比在 CI 处于观察期（`continue-on-error`），尚未在实机 redex 上验证过一轮；art 模式依赖常驻设备，配方见 `tools/oracle/README.md`。baksmali 不覆盖未建模 section。
- 040/041 语料缺实物：提取脚本就绪，041 写回语义已冻结（独立文件约定），实物到位跑 ART oracle 复核（见 doc/corpus_040_041_notes.md）。
- type/proto/field/method 的 add* 去重是线性扫描（字符串已有哈希 intern 索引）：dexperf 合成 6.4 万方法时生成侧 O(n²) 可感（~7s），读/重建路径不受影响；SemIndex 式哈希表留作优化项。
- 没有 APK/多 dex 容器语义（裁决维持：单文件字节核的边界，上层持有）。

## 下一批

补齐路线全文见 [doc/roadmap.md](doc/roadmap.md)（场景矩阵、M0–M5 里程碑与
验收即 goal 边界）。当前批次：

- 场景矩阵 M0–M5 与 S1/S2 已完成，redex 观察期、ART 设备与 041 实物仍在闭环（见 doc/roadmap.md 状态横幅）。
- 外部依赖两条：ART 常驻设备（art oracle + 040/041 实物语料 + 提取脚本真机
  跑通）；redex 双边对比观察期转门禁。
- 优化项：add* 家族哈希去重索引（SemIndex 对应物）；如需超越 64K method_ids
  的场景归上层多 dex 编排（库外裁决不变）。
