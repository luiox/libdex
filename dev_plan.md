# dev_plan.md — libdex 落地账目

只记已经跑通的实现事实，不按版本号记账。基线提交 `f98c911` 是原型，`0.0.1` 只是构建占位。

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

## 已实现：core/type MVP（未发布，2026-10-23）

- 模块边界：删除 `dex/consumer`，库面收敛为 core / type；摘要不再是库 API。
- core：新增 SLEB128；`parseCodeItem` 解析 try_item 与 encoded_catch_handler，展平为 TryBlock/CatchHandler；catch-all 的判定按 `size <= 0` 修正（真实语料与参考实现暴露的符号错误）。
- type：字段类型、方法描述符、类名与数组维数解析，统一 Result 错误；不查表、不解析泛型签名。
- ir：曾加入只读 CodeDom（label、展平 try、结构 issues）；后因库不定义 AST 的边界裁决整体删除，见下一节。
- 测试：57 个用例全绿（含两份真实语料的解析、往返与全方法体指令解码）。
- 参考：jumanji144/dex（Java，core 约 1.9 万行）采用 item+codec 低层模型加 tree/definitions 高层可编辑模型；低层 item+codec 是库的方向，高层树留给使用方 adapter。

## 已实现：值编码与注解族（未发布，2026-10-23）

- 参照 libjbc 的保真机制重新校准：条目带源区间、lazy 结果挂槽、未建模区段不猜语义；值编码保留原始宽度，不按最小形态归一化。
- encoded_value：18 种类型码全覆盖；`value_arg` 原样保存在每个节点上；数组/注解递归与 256 层深度上限；引用类索引按 `value_arg+1` 字节小端零扩展读取（真实语料暴露的错误：此前误按 ULEB128）。
- 编码面：`writeEncodedValue`、`writeEncodedArray`、`writeEncodedAnnotation` 按所记宽度写回；载荷超出宽度、布尔与 value_arg 不一致、浮点低位非零返回 `Unencodable`，不静默截断。
- 注解族：annotation_item（visibility 原样保存）、annotation_set_item、annotation_set_ref_list、annotations_directory_item、encoded_array_item，各自带 `ByteSpan raw`；DexFile 按偏移懒解码并缓存，类级入口 `classAnnotations`/`staticValues`。
- 测试：71 个用例全绿。合成用例覆盖值类型、非最小宽度、深度上限、畸形计数与容器条目；真实语料遍历全部注解目录与参数 set，静态初值数组与 annotation_item 均做解码→重编码字节比较。
- 指令保真：`Insn` 增加原始 code unit 视图 `raw`；高字节非零的 nop 变体不再只保留语义形态，编码器据此原样写回。
- 注解容器写回：annotation_item、annotation_set_item、annotation_set_ref_list、annotations_directory_item、encoded_array_item 的 item writer 落地；合成与真实语料都做整条目解码→编码字节比较。
- 已知缺口：低层条目覆盖在下一节补齐；整文件重编码写回随后落地（见 canonical 重建一节）。

## 已实现：精确指令编码与 adapter 边界（未发布，2026-10-23）

- 库面收敛：删除 `dex/ir` 与只读 CodeDom（label、展平 try、结构 issues 都属于语义视图，是使用方 adapter 的职责，不是保真 DOM）；xmake、umbrella 与真实语料测试同步。
- 指令编码器：`encodeInsn`/`encodeInsns` 覆盖 26 种定长格式与三类 payload；按 opcode 的定长格式逐位写入，不做 const 形态提升或合并；域宽溢出返回 `OperandOverflow`，payload 落在奇 code unit 地址返回 `MisalignedPayload`。
- 保真细节：10x/20t/30t/32x 的未用高位、35c/45cc 的 G 与未用参数 nibble、fill-array-data 的补齐字节都在 `Insn::raw` 与当前指令一致时原样沿用。
- 修正 35c/45cc 的 nibble 读法：unit0 是 `A|G|op`，A（高 nibble）是参数个数、G 是 bits 11..8 的第五个寄存器；此前解码把两者读反，测试 fixture 也按错误读法编写。真实语料逐方法体解码→编码字节一致暴露了该问题，修复后全部通过。
- 测试：71 个用例全绿；真实语料的每个方法体都过 `encodeInsns` 逐字节比对，合成用例覆盖编码溢出、坏格式与 payload 对齐错误。

## 已实现：低层条目补全（未发布，2026-10-23）

- debug_info：状态机全操作码解码为 `DebugOp`（ADVANCE_PC/LINE、START_LOCAL[_EXTENDED]、END_LOCAL、RESTART_LOCAL、SET_PROLOGUE_END、SET_EPILOGUE_BEGIN、SET_FILE、special 区间）；`raw` 覆盖到 END_SEQUENCE；header 与每条操作保留原始字节，`writeDebugInfo` 对非空 raw 原样写回（含非最小 ULEB/SLEB），只有清空 raw 才按字段重编码；special 字段与 opcode 不自洽时拒绝。
- call_site/method_handle：无头部计数，按 map_list 读取定长表；method_handle 的两个 unused 字段原样保留；call_site 值复用 encoded_array 解码，越界返回 BadIndex。
- 未建模 map section：`RawSection` 记录原始 type 值、声明条目数与源区间（到下一 section 或文件尾，含对齐填充），未知类型不再只剩目录项。
- 结构写回：`writeClassData` 由绝对索引重算差分并校验严格递增；`writeCodeItem` 按 handlerIndex 重算 handler_off、保持 handler 共享、奇数 insns 在 tries 前补对齐；虚构与真实语料的 class_data/code_item 均做整条目字节比较。
- LEB128：补最小编码的 ULEB128/SLEB128 写出。
- fixture 扩展：debug_info、method_handle、call_site 与 0x7F00 未知 section 全部进入合成样本；真实语料的两份 dex 是 stripped 产物（无 debug_info/call site），相关路径由 fixture 覆盖。
- 测试：82 个用例全绿。

## 已实现：canonical 整文件重建（未发布，2026-10-23）

- 布局：`buildDex(DexFile&, const BuildOptions&)` 输出 header、五张 ID 表、class_defs、call_site_ids、method_handles，数据区依次为 string_data、type_list、encoded_array、annotation_item、annotation_set、annotation_set_ref_list、annotations_directory、debug_info、code_item、class_data、未建模 section、map_list；各 section 内条目按格式要求的对齐落位。
- 偏移回填：string_ids 的 data_off，proto 的 parameters_off，class_defs 的 interfaces/annotations/class_data/static_values，call_site 的 call_site_off，code_item 的 debug_info_off，class_data 的 code_off；map_list 按新偏移重建，checksum/signature 重算。
- 保真：string_data 与 type_list 原字节复制（含非最小 ULEB 与共享 type_list）；debug_info、encoded_array、annotation_item 走精确重编码；class_data/code_item 按新偏移重编码；注解目录/set/ref list、code_item、debug_info、class_data、encoded_array 按旧偏移去重，共享关系保持；method_handle 的 unused 字段保留；未建模 section 默认按原字节透传，可关闭。
- 方法体替换：`BuildOptions::codeReplacements` 按 method_idx 替换 insns 与 CodeItem 头部/tries；`debugInfoOff` 解释为源文件偏移并重映射。同一 code_item 被多个方法共享时，未替换的方法保留原条目，替换项单独产出。
- 错误面：041 与非空 link 区返回 `NotModeled`；重建时再次解码失败返回 `SourceUnreadable`；替换项重复、指向不存在或无可替换方法体的方法、引用缺失返回 `InvalidModel`；条目超出编码域宽返回 `Unencodable`。
- 测试：89 个用例全绿。合成 fixture 验证重建后重读为 Validated、完整性字段有效、map 偏移递增、未知 section 保留/可关闭、方法体替换与错误路径、二次重建字节稳定；两份真实语料的整文件重建完成逐方法指令字节比较、新注解与静态初值偏移遍历及二次重建字节稳定。
- 已知缺口：无条目级 dirty 状态；无可达性之外的死条目保留策略；未建模 section 内部的绝对偏移不回填；041 container 语义仍待 oracle 冻结。

## 已实现：baksmali 对拍与 CI（未发布，2026-10-23）

- `tools/dexbuild`：`rebuild` 走公开的 `readDex` → `buildDex` 路径重建 dex；`fixture` 输出与单测相同的 035 合成样本。
- `tools/oracle/check.sh`：固定 baksmali 2.5.2，从 Maven Central 拉取 baksmali/dexlib2/util/guava/jcommander/jsr305/failureaccess 到 `.oracle-cache/`（gitignore），比较原文与重建产物的 smali 文本，Windows 下自动做 MSYS→Windows 路径转换。
- 本地结果：合成 fixture、level1（5528 B）与 level2（719560 B）的 smali diff 均为空；重建产物被 dexlib2 完整解析。
- CI：`.github/workflows/ci.yml` 在 Ubuntu 与 Windows 上跑 xmake 3.0.9 构建、89 个单测与 fixture 对拍；真实语料不提交，CI 不跑。
- 开源面：MIT、README 的 Under Construction 标识、CONTRIBUTING 与对拍说明。
- 已知缺口：ReDex 写回参照与 ART 实机验证未接；baksmali 不覆盖未建模 section；CI 语料只有合成 fixture。

## 下一批

1. 条目级修改状态与 ID 表追加护栏：dirty 标记、五表只追加与容量上限、追加后索引越界检查。
2. adapter 原语：给使用方 adapter 提供布局与选题辅助（指令宽度、const 取值域、索引上限、分支重算），但不在库内定义 AST。
3. oracle 扩展：ReDex 写回参照与 ART 实机验证；保持 baksmali 为文本 oracle，先定不一致时的仲裁规则。
4. 语料矩阵与卫生：补齐 035/037/038/039/040/041 样本与哈希清单，第三方 APK 只入哈希与复现脚本。
