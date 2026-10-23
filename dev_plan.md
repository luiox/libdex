# dev_plan

libdex 的当前能力、缺口与下一步。只记已经跑通的事实，不按版本号记账。

## 当前能力

- 解析 035–041 的 header、map_list、五张 ID 表、class_defs、call_site_id、method_handle；string_data、class_data、code_item、type_list、注解族、encoded_array、debug_info 懒解码并缓存。041 的 container 字段只读取。
- 未建模 map section 记录原始区间；未修改写回原字节透传。
- 指令层覆盖 26 种定长格式与三类 payload，按 opcode 精确编码；`Insn` 保留原始 code unit，不合并 const 形态。
- 值编码覆盖 18 种类型，保留 `value_arg`；注解族、encoded_array、debug_info 有精确 item writer。
- `writeClassData` / `writeCodeItem` 重算差分与 handler_off，保持 handler 共享。
- `buildDex` 生成 canonical 布局：回填字符串、type_list、class_data、code、注解与 call_site 偏移，重建 map_list，重算 checksum/SHA-1；支持按 method_idx 替换方法体。
- baksmali 2.5.2 文本对拍：合成 fixture、level1（5528 B）与 level2（719560 B）smali diff 均为空。
- CI 在 Ubuntu 与 Windows 上跑单测和 fixture 对拍；真实语料不提交。
- 本地带真实语料 89 个用例全绿。

## 已知缺口

- 041 container 语义未冻结，`buildDex` 明确拒绝；非空 link 区同样拒绝。
- 没有条目级 dirty 状态；修改面目前只有方法体替换。
- 没有 ID 表追加护栏；五表只追加的约定尚未落成 API。
- `buildDex` 丢弃不可达的建模条目；未建模 section 内部的绝对偏移不回填。
- MUTF-8 只给字节视图，不做码点校验；type_list 不校验元素索引。
- ReDex 写回参照与 ART 实机验证未接线；baksmali 不覆盖未建模 section。
- 没有 smali 文本层与 APK 容器语义。

## 下一批

- 条目级修改状态与 ID 表追加护栏。
- adapter 原语：指令宽度、const 取值域、索引上限、分支重算；库内仍不定义 AST。
- oracle 扩展：ReDex 与 ART 实机；先定 oracle 不一致时的仲裁规则。
- 语料矩阵：补齐 035/037/038/039/040/041 样本与哈希清单。
