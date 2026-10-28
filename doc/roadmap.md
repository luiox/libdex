# libdex 补齐路线

目标：把 libdex 补到 libjbc 的完善度——真实工具链场景覆盖 ≥95%，每个场景有
oracle 对拍背书，而不是"API 存在"。本文是 goal 边界的真源；每批完成的事实
记账仍归 [dev_plan](../dev_plan.md)，裁决归 [design](design.md)。

> **状态（2026-10-28）**：M0–M5 与 S1/S2 已完成，场景矩阵除三条外部依赖
> （ART 实物 oracle、041 实物复核、redex 观察期转门禁——都不阻塞 API 面）
> 外全绿。本文保留为 goal 边界的历史记录，后续新场景按批次追加矩阵行。

## 覆盖度口径

覆盖度按场景矩阵计，计入标准是三条齐：库内 API 可完成、有测试背书、过
oracle 对拍（baksmali 门槛 + redex/ART 可用时）。矩阵：

| # | 场景 | 现状 | 里程碑 |
|---|---|---|---|
| 1 | 读取/枚举 035–041 全条目（头、ID 表、类、注解、debug） | 已覆盖 | — |
| 2 | 保真透传写回（未修改字节恒等） | 已覆盖 | — |
| 3 | canonical 重建（重排 + 校验字段重算） | 已覆盖 | — |
| 4 | 增量编辑（保留源布局、无编辑字节恒等） | 已覆盖 | — |
| 5 | 全量改名/索引重排（含 debug/注解/指令内重写） | 已覆盖 | — |
| 6 | 成员增删改、新类注入、access_flags 覆盖 | 已覆盖 | — |
| 7 | 方法体整段替换（按 method_idx 换字节） | 已覆盖 | — |
| 8 | 注解/静态初值/字符串 intern 的读写与新建 | 已覆盖 | — |
| 9 | 指令级解码/编码 + 寄存器域与 payload 原语 | 已覆盖 | — |
| 10 | 方法体结构编辑（插删指令、改控制流、try/handler 联动） | 已覆盖 | M1 ✅ |
| 11 | 从零构建 dex / 从零建方法（含控制流） | 已覆盖 | M2 ✅ |
| 12 | ID 表生命周期（删除后回收、去重压缩 vacuum） | 已覆盖 | M3 ✅ |
| 13 | 数据流分析（寄存器帧、CFG、可达性） | 已覆盖 | M4 ✅ |
| 14 | 041 container 字段读/写语义 | 已覆盖（canonical 重置 `(file_size,0)`，实物复核待） | M5 ✅ |
| 15 | 畸形输入防御：错误族全覆盖 + 诊断分类学 | 已覆盖 | M0/M5 ✅ |
| 16 | 泄漏/生命周期硬化（ASan 门禁） | 已覆盖 | M0 ✅ |
| 17 | 大文件性能基线（防 decoder 回归） | 已覆盖 | M5 ✅ |
| 18 | oracle 常驻（baksmali 门禁 / redex / ART 设备） | baksmali 门槛，redex 观察期，ART 待设备 | M0 收口 |

| 19 | smali 反汇编（DexFile → 文本，baksmali 兼容文法） | 已覆盖 | S1 ✅ |
| 20 | smali 汇编（文本 → DexFile，label 解析 + 形态选择） | 已覆盖 | S2 ✅ |

**库外事项（不计入缺口，即剩余 ~5%）**：APK/多 dex 容器、cdex/odex/vdex
写回、跨文件全局索引。这是 libjbc 把跨类编排归 mbase 的同一裁决：单文件
字节核的边界，上层持有。smali 文本层原列库外，随 libsmali 入仓翻案（S1/S2）。
两条未闭环的外部依赖：ART 实物 oracle（待常驻设备）、041 实物复核（写回
语义已按独立文件约定冻结，实物到位跑 ART oracle 复核）。

## 对照基线

libjbc（v0.4.x，src 约 2.1 万行）已验证的机制与 libdex 的差口：

| libjbc 机制 | libdex 现状 | 差口 |
|---|---|---|
| lazy ClassFile DOM + 属性四态脏追踪 | lazy DexFile + incremental Entry 透传/重编码 | 完成 |
| attr/insn codec 分层（条目族一文件） | 已对齐（class_data/code_item 独立 codec） | 完成 |
| CodeDom + `InsnId{owner,slot,gen}` 值句柄 | CodeUnit 槽表 + 值句柄（M1） | 完成 |
| ClassSession promote/lower + relocation contract | CodeUnit ↔ decode/encode 为唯一 code 发射通道（M1 收口） | 完成 |
| CodeEditor（erase 双策略、StillUsed 协议） | CodeUnit insert/erase 双策略 + 地址联动（M1） | 完成 |
| 语义 intern 家族 + SemIndex 去重表 | intern 家族「命中复用、miss 追加」纪律成文；字符串有哈希 intern 索引，type/proto/field/method 去重为线性扫描（SemIndex 式哈希表留作优化项） | 完成（优化项遗留） |
| MethodEditor 门面（open/append/commit） | MethodEditor open/append/label/commit（M2） | 完成 |
| cp_compact（死常量消除 + 全引用重映射） | vacuumIds 显式 opt-in（M3 翻案落地） | 完成 |
| analysis 帧引擎（到达帧、Strict 域） | buildCfg + analyzeFrames 双档帧引擎（M4；SMT 不做） | 完成 |
| ASan 泄漏门（自检防假绿 + new/delete 平衡） | libdex_leak_check 自检 + 语料走查（M0；M4 路径已纳入） | 完成 |
| visitor 禁令门禁 | 无 visitor，design 已成文禁令 | 保持 |

## 里程碑

每批 = 提交序列 + 测试 + design/dev_plan 记账；里程碑验收即 goal 边界。
顺序上 M0 先行（便宜、护住后面所有批次），M1 是长杆并解锁 M2/M4，M3 可与
M2 并行穿插，S1/S2 接在 M2 之后（依赖 CodeDom 与构建门面），M5 收尾（其中
041 实物、ART 设备两条外部依赖随时并行推进）。CodeDom 的立项裁决：smali
汇编器没有 label 承载的方法体模型做不出来——libsmali 入仓即翻案原
「CFG 归 adapter」条款，libsmali 建在库内 CodeDom 上（design.md「分层」）。

### M0 质量基线（1–2 批）

- ASan 泄漏检查 target：借 libjbc §20/§23 的做法——独立 asan target（不与
  gtest 同链，MSVC 下 /fsanitize=address 改 STL ABI），真实语料
  读→全解码→写回零报告，`new/delete` 计数平衡，插桩自检防假绿。
- 畸形输入盘点：`malformed_test` 对照 error.hpp 错误族清单逐族核对，补
  截断/越界/自引用环的结构化样本；缺口列入 M5 收尾。
- CI 收口：redex 双边对比出观察期转门禁；040/041 实物到手后进语料矩阵与
  `LIBDEX_REAL_DEX_DIR` 测试。
- 验收：单测 + oracle + ASan 三绿；错误族覆盖表入 dev_plan。

### M1 方法体 CodeDom（长杆，3–5 批）

- 模型：`CodeUnit` 拥有指令槽表 + 程序序；分支/try/handler/payload 用值句柄
  与 label 绑定；`InsnId{owner,slot,gen}` 同构 libjbc（gen 防 ABA，跨
  owner 结构性拒绝）；不引入 visitor。
- 编辑：insert/replace/erase；erase 双策略（引用仍在时 `Err(StillUsed)` 或
  级联删除，调用方显式选）；地址重算收编为 lower 的一部分，try/catch 区间
  与 handler 地址随布局联动。
- 发射统一：`CodeUnit ↔ decodeInsns/writeCodeItem` 的 promote/lower 成为
  唯一 code 发射通道，`buildDex` 与 incremental 的 code 段收编为同一
  lower——两条重建路径不再各自维护指令编码（libjbc relocation contract 的
  对应物）。
- 保持的裁决：形态选择不自动提升（const 合并/nop 填充仍显式）；8/16 位
  分支溢出的报错策略成文进 design；label 解析归编辑器，CFG 推导归 M4。
- 验收：26 格式 × 3 payload 往返单测；真实语料"仅方法体内编辑"的增量
  恒等不回退；baksmali 对拍；句柄误用（跨 owner/悬挂/gen 过期）拒绝测试。

### M2 构建门面（2–3 批）

- `MethodEditor`：open/append/label/commit；`addMethodWithBody` 直线体一步
  落盘；批量入口对未绑定 label 按形状拒绝控制流（对齐 libjbc
  method_editor_test 的六类误用清单）。
- 从零构建：空 DexFile 构造 + 五表/class_defs/map 发射，与既有"新增类"
  共用 canonical 发射器；产出的 dex 过 baksmali（有设备时过 ART）。
- intern 家族语义统一：字符串/类型/proto/字段/方法/call_site/method_handle
  的"命中复用、miss 追加"纪律与去重键逐一成文（对齐 SemIndex 的去重表
  做法），`IdTableFull` 边界保持。
- 验收：从零构建的方法体可被 baksmali 反汇编且与源语义一致；误用序列
  不留半成品（失败回滚纪律与 builder_edit 一致）。

### M3 ID 表生命周期（2 批）

- vacuum（翻案 design「压缩与 vacuum 不做」为**显式 opt-in**）：引用闭包
  收集 → 存活条目重排 → 全引用重写（code / debug_info / annotation 族 /
  encoded_value / class_data / call_site / method_handle）；未建模 section
  在场时拒绝（与 `UnmappedRawSection` 纪律一致）。
- 与增量路径的裁决先成文再实现：intern-only 编辑是否解除 `NotIncremental`
  ——不双轨漂移，裁决记录进 design。
- 验收：删除成员后 vacuum 产物 baksmali 一致、表长收缩；压缩前后语义
  oracle（redex/ART 可用时）通过。

### M4 分析层（2–3 批）

- 逐指令到达帧：寄存器类型/宽度域（cat1/cat2 配对、引用 → type_idx）、
  异常边、monitor 对；best-effort 与 Strict 双档（对齐 libjbc §10.1 三态
  策略）；jsr/ret 类比物——DEX 无子程序，等价物是 move-result 的
  invoke 配对约束。
- CFG 从 CodeDom 派生（依赖 M1）；帧引擎在语料上 100% 可解析，与 ART
  接受性一致（接受 ≈ 帧可闭合；拒绝样本人工归因入账）。
- 验收：帧结果单测 + 语料 oracle + 畸形不误报；不做全程序视图（同基线
  裁决，跨类归上层）。

### S1/S2 libsmali（CodeDom 之后的文本层，4–6 批）

- S1 反汇编器：DexFile → `.smali` 文本。类/字段/方法头与 access flags、
  26 格式指令文本、label 合成（分支目标/switch payload/try 区间/handler）、
  注解与静态初值、debug 投影（.source/.line/.local 族）。文法对齐 baksmali
  可读子集；每类一文件。
- S2 汇编器：文本 → DexFile 编辑（新建或既有文件）。词法/递归下降、
  寄存器映射（pN → vN）、形态选择（字面量宽度、分支距离、const-string
  jumbo）、label 解析、payload/try/handler/注解/初值落位；复用
  MethodEditor/DexBuilder 与 intern 家族。
- 往返 oracle：our_disasm → our_asm → baksmali 对拍（复用 check.sh 的
  sort_methods 纪律）；语料四版本逐个过。红温即修，往返封闭以反汇编器
  自产文本为准。
- 验收：语料往返后 baksmali 文本一致；汇编程文法错误 fail-loud 不留半成品。

### M5 边界冻结与硬化（持续 + 收尾批）

- 041 container 语义冻结：设备实物 → `container_size`/`header_offset` 实测
  → 写回裁决（重置 `(file_size, 0)` 还是保留原值）→ `buildDex` 解除拒绝。
- 大文件性能基线：≥10 万方法级 dex 的解析/重建计时入账，只防回归不激进
  优化。
- 错误诊断分类学收口：ReadError/WriteError 逐码语义文档化进 design；M0
  盘点出的畸形缺口清零。
- 验收：场景矩阵终版入 dev_plan，覆盖度复核 ≥95%。

## 翻案清单

design.md「不做」随本路线显式翻案两条，其余维持：

| 原条款 | 翻案为 | 里程碑 |
|---|---|---|
| 库内方法体 AST | CodeDom（值句柄、无 visitor） | M1 |
| 压缩与 vacuum | 显式 opt-in 的 vacuum | M3 |
| visitor 形状 | **维持禁令**（M1/M4 的判据与 libjbc §26 同源：数据形态，回调推送即换皮） | — |

## 成本形状

src 预计 1.2 万行 → 约 2 万行（与 libjbc 同量级），测试翻倍以上。M1 占
大头（约 2.5–3 千行 src + 同量测试）。批次口径不变：只记跑通的事实，
里程碑一次收账。

## 相关

- [design](design.md)：分层契约与裁决（含翻案落地）。
- [dev_plan](../dev_plan.md)：批次事实记账。
- [corpus_040_041_notes](corpus_040_041_notes.md)：M5 的外部依赖细节。
- libjbc 参照：`docs/design.md`（CodeDom/session/analysis 拓扑）、
  `docs/classfile-decision-matrix.md`（12 决策点）、
  `src/jbc/ir/code_dom.*` / `code_editor.*`（M1 直接参照实现）。
