# dev_plan.md — libdex 落地账目

只记已经跑通的实现事实，不按版本号记账。首个基线提交前不存在发布版本，`0.0.1` 只是构建占位。

## 已实现：只读核（未发布，2026-10-23）

- 起仓：从 morpher 工作区的 libjdex 立项草案起独立仓，实现名 libdex；xmake 接线、MIT 许可、包仓依赖（libca 0.0.16 / libjstr 0.0.3）落地。
- 字节底座：源字节用 libca `Bytes` 持有、视图用 `ByteSlice`、小端读取用 `get_*_le`，libdex 只保留薄 `Reader` 做 offset 切片与错误映射；Result 错误码与诊断，容忍非最小编码的 ULEB128 读取，adler32 与 SHA-1 完整性工具。
- DOM：单 DexFile 拥有源字节、header、map_list、五张 ID 表与 class_defs；string_data、class_data、code_item、type_list 按需解码并缓存。
- 访问面：类/父类/来源文件、字段与方法的名字/owner/类型、原型参数、接口列表、class_data 目录、code_item 目录。
- 写回：未修改原字节透传；无源字节返回 `MissingSource`。
- 健壮性：表区间越界 Err；悬垂索引、map 计数不符、完整性失败记诊断并进 `Recovered`；class_data 的计数先按 ID 表长度与剩余字节数双重封顶，避免畸形输入触发放大分配。
- 测试：合成 035 fixture 覆盖解析、懒解码、畸形输入、完整性已知向量与字节级往返，另有 LEB128 规范/冗余/溢出/截断边界用例；真实语料门控用例在有语料时执行。
- 真实语料：本地两份真实 dex（5.5 KB 与 719 KB）通过解析、字节级往返；两份的 checksum 均有效而 SHA-1 过期，按设计进 `Recovered`，不拦读取。语料不入库。
- consumer/摘要扫描已从库面删除：它是立项草案的验收面，不是库能力。
- 已知缺口：无真实 041 语料（`container_size`/`header_offset` 语义待 oracle 冻结）；MUTF-8 未做码点校验；type_list 未校验元素索引；dexlib2/baksmali/ReDex 对拍器未接线。

## 已实现：指令层（未发布，2026-10-23）

- 元数据：0x00–0xff 操作码表，224 个已定义操作码；26 种定长编码格式与宽度查询；未定义槽返回 `Unknown` 条目，查询不抛异常。
- 解码：`decodeInsns` 覆盖 10x/12x/11n/11x/10t/20t/22x/21t/21s/21h/21c/23x/22b/22t/22s/22c/30t/32x/31i/31t/31c/35c/3rc/45cc/4rcc/51l；每条给出地址、宽度、寄存器、索引、立即数与分支偏移；21h 立即数已按 opcode 移位，35c/3rc 的寄存器约定分开表达。
- payload：packed-switch、sparse-switch、fill-array-data 三类，保留源字节视图并提供按索引取 key/target 的访问器；校验偶数地址与尺寸边界；switch case target 相对 switch 指令地址。
- 容错：低字节为 0、高字节非 payload 标识的 code unit 按 ART 的宽容度当 nop；未定义操作码、指令截断与坏 payload 返回 `InsnError`，不交付半截指令流。
- 测试：合成用例覆盖全部格式、三类 payload、立即数符号扩展与错误路径；真实语料逐方法体解码，核对宽度和等于 `insns_size`、31t 引用的 payload 类型、switch case 与普通分支目标落在指令边界。
- 已知缺口：`Insn` 的 payload 视图借用入参 `ByteSlice`；无指令编码器、方法内 CFG 与 debug_info。

## 已实现：core/type/ir MVP（未发布，2026-10-23）

- 模块边界：删除 `dex/consumer`，库面分 core / type / ir；摘要不再是库 API。
- core：新增 SLEB128；`parseCodeItem` 解析 try_item 与 encoded_catch_handler，展平为 TryBlock/CatchHandler；catch-all 的判定按 `size <= 0` 修正（真实语料与参考实现暴露的符号错误）。
- type：字段类型、方法描述符、类名与数组维数解析，统一 Result 错误；不查表、不解析泛型签名。
- ir：只读 CodeDom 持有源字节共享所有权，推导分支/switch/payload/try label，展平 try 区域，结构问题进入 issues 而不阻断构建。
- 测试：57 个用例全绿（含两份真实语料的解析、往返、全方法体指令解码与 CodeDom 构建）。
- 参考：jumanji144/dex（Java，core 约 1.9 万行）采用 item+codec 低层模型加 tree/definitions 高层可编辑模型，两遍 unmap 分配池索引，CodeCodec 用不动点收敛分支宽度；这些是下一阶段 builder 的直接参照。

## 下一批

1. 低层 item 覆盖：annotations/encoded_value、静态初值、debug_info（状态机）、call site/method handle。
2. 高层模型与写回：ClassDefinition/Member/Code/Instruction 对象、两遍池分配、class_data 按索引排序、canonical 布局、checksum/signature 重算。
3. 指令编码器：格式编码、分支宽度收敛、payload 对齐与 label 回填。
4. oracle 接线：dexlib2 结构对拍、baksmali 文本对拍、ReDex 写回参照；先定仲裁规则再跑对拍。
5. 语料矩阵与卫生：补齐 035/037/038/039/040/041 样本与哈希清单，第三方 APK 只入哈希与复现脚本。
