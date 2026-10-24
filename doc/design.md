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

`buildDex` 只输出可达条目，不可达的建模条目会丢弃；string_data 与 type_list 原字节复制，其余条目精确重编码。未建模 section 默认透传，可选择丢弃；其中若含绝对偏移不会回填。041 与非空 link 区返回 `NotModeled`。

## ID 表与字符串池

DEX 要求 string_ids 按 UTF-16 排序，type/proto/field/method 按各自键排序。新增或重命名不能只追加，必须重排序并重写所有内嵌索引。

字符串这一层已经接通：`internString` 接受 MUTF-8，`internUtf8` 接受标准 UTF-8，返回可写入 `nameIdx`/`sourceFileIdx`/指令索引的 string 索引。`buildDex` 把所有源字符串与自有字符串合成 canonical 池：按 UTF-16 code unit 排序、去重、建立旧→新映射，再重写 type/proto/field/method 的字符串索引、class_def 的 source_file_idx、const-string/const-string/jumbo、debug_info 的参数名与 SET_FILE、encoded_value 的 String、注解元素名。旧索引全部不动时跳过指令与值重编码，保持原字节。

字段与方法这一层也已接通：`field_ids` 按 (class, name, type)、`method_ids` 按 (class, name, proto) 重排，重建同步重写 class_data 的成员索引并按新索引重排四个列表、注解目录的成员索引、指令中的字段/方法索引、method_handle 的 target、encoded_value 的 Field/Enum/Method。重命名不再要求保持原表顺序。

type 与 proto 表仍不重排：字符串重命名如果破坏 type 表描述符顺序返回 `UnsortedTables`；改类描述符需要 type 表的全量索引重写，留待后续。字符串或成员索引发生变化而仍保留未建模 section 时返回 `UnmappedRawSection`，因为无法迁移其中可能存在的索引；显式关闭 `keepUnknownSections` 才能继续。const-string 不自动提升为 jumbo，新索引超出 16 位返回 `Unencodable`，形态选择仍归 adapter。

class_defs 可以删除与重排；删类不回收 ID 表条目。容量：type/proto/field/method 各 65536，string 是 u32；`buildDex` 在入口检查容量与表内索引，越界返回 `InvalidModel`。

## 错误

错误走 `Result`，不抛异常。结构性问题返回 Err；语义问题（校验和不符、悬垂索引、map 计数不符）记诊断并将 `ParseState` 置 `Recovered`，模型仍可读。

`ParseState` 只有 `Validated` 与 `Recovered`；结构损坏不产出半截模型。

## 指令

`decodeInsns` 覆盖 26 种定长格式与三类 payload，给出地址、宽度、寄存器、索引、立即数与分支偏移；未定义操作码返回错误。

`encodeInsn`/`encodeInsns` 按 opcode 的定长格式写回，域宽溢出返回 `OperandOverflow`，payload 错位返回 `MisalignedPayload`。不自动插 nop、不改变形态。

库还给 adapter 提供编辑原语：`constFormFits`、`insnIndexLimit`、`insnBranchTarget`/`setInsnBranchTarget`、`recomputeInsnAddresses`。label、CFG 与 const 形态选择仍归 adapter。

payload 不展开成 target 数组，保留源字节视图；switch target 相对 switch 指令地址。

## 类型与容器

type 层只解析字段类型与方法描述符，不查 ID 表、不解析泛型签名。

单文件职责；classes2.dex、APK 容器、resources.arsc 与 AXML 都在库外。

## 对拍

文本 oracle 是 baksmali 2.5.2（dexlib2）：原文件与 `buildDex` 产物分别反汇编，smali 文本必须一致。它覆盖指令、try/catch、注解、静态初值、debug 行号与访问标志。

baksmali 不覆盖未建模 section，也不等于 ART 接受；与 AOSP DEX 规范冲突时以规范为准。ReDex 与 ART 实机验证尚未接线。

真实语料不入库，通过 `LIBDEX_REAL_DEX_DIR` 注入；第三方 APK 只允许哈希清单与复现脚本。

## 不做

- odex / vdex / art / compact dex。
- APK、resources.arsc、AXML 与多 dex 模型。
- type/proto/field/method 表的重编号与条目增删；压缩与 vacuum。
- visitor 形状与库内方法体 AST。
- opcode 形态合并或自动提升。
- 修改后字节 diff 最小化。

## 相关

- [README](../README.md)：构建与最小示例。
- [dev_plan](../dev_plan.md)：实现进度与下一步。
