# dev_plan

libdex 的当前能力、缺口与下一步。只记已经跑通的事实，不按版本号记账。

## 当前能力

- 解析 035–041 的 header、map_list、五张 ID 表、class_defs、call_site_id、method_handle；string_data、class_data、code_item、type_list、注解族、encoded_array、debug_info 懒解码并缓存。041 的 container 字段只读取。
- 未建模 map section 记录原始区间；未修改写回原字节透传。
- 指令层覆盖 26 种定长格式与三类 payload，按 opcode 精确编码；`Insn` 保留原始 code unit，不合并 const 形态。
- 值编码覆盖 18 种类型，保留 `value_arg`；注解族、encoded_array、debug_info 有精确 item writer。
- `writeClassData` / `writeCodeItem` 重算差分与 handler_off，保持 handler 共享。
- `buildDex` 生成 canonical 布局：回填字符串、type_list、class_data、code、注解与 call_site 偏移，重建 map_list，重算 checksum/SHA-1；支持按 method_idx 替换方法体。
- `internString` / `internUtf8` 追加或复用字符串；`buildDex` 按 UTF-16 合并排序去重，重写 ID 表、const-string、debug_info、encoded_value 与注解元素名中的字符串索引。
- 类型/字段/方法改名：`buildDex` 按 DEX 排序键重排五张 ID 表与 class_defs，重新编码 type_list，重写 class_data（并按新索引重排四个列表）、注解目录、指令、catch、debug_info 局部变量、method_handle 与 encoded_value 中的全部索引。
- `addType`/`addProto`/`addField`/`addMethod` 追加或复用 ID 表条目并返回索引；表满返回 `IdTableFull`。新增条目只进 ID 表，不挂到 class_data。
- 任何表索引移动与保留的未建模 section 冲突返回 `UnmappedRawSection`。
- `buildDex` 入口检查 ID 表容量与表内索引；悬垂索引、非法 method_handle 与零 call_site 返回 `InvalidModel`。
- adapter 原语：`constFormFits`、`insnIndexLimit`、`insnBranchTarget`/`setInsnBranchTarget`、`recomputeInsnAddresses`。
- baksmali 2.5.2 文本对拍：合成 fixture、level1（5528 B）与 level2（719560 B）在方法块顺序规范化后 diff 均为空。
- CI 在 Ubuntu 与 Windows 上跑单测和 fixture 对拍；真实语料不提交。
- 本地带真实语料 108 个用例全绿；真实语料的成员/类型改名重建与二次重建固定点通过。

## 已知缺口

- 041 container 语义未冻结，`buildDex` 明确拒绝；非空 link 区同样拒绝。
- 没有条目级 dirty 状态；重建总是全量 canonical。
- ID 表条目删除未提供；新增成员只进 ID 表，class_data 挂载与 class_def 新增留待后续。
- ID 表索引重排不能跨未建模 section：保留 section 时只要旧索引移动就拒绝重建。
- `buildDex` 丢弃不可达的建模条目；未建模 section 内部的绝对偏移不回填。
- 源字符串的 MUTF-8 在重建时校验 UTF-16 长度；type_list 元素索引越界返回 `InvalidModel`。
- ReDex 写回参照与 ART 实机验证未接线；baksmali 不覆盖未建模 section。
- 没有 smali 文本层与 APK 容器语义。

## 下一批

- 条目级 dirty 状态：只重编码被改条目，避免全量 canonical。
- 类成员注入：把新增方法/字段挂进 class_data、生成代码布局，并支持新增 class_def。
- adapter 原语继续补齐：寄存器域、payload 重建与批量编辑辅助。
- oracle 扩展：ReDex 与 ART 实机；先定 oracle 不一致时的仲裁规则。
- 语料矩阵：补齐 035/037/038/039/040/041 样本与哈希清单。
