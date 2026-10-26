# oracle 对拍与仲裁规则

libdex 的"正确"由外部 oracle 定义：库内 reparse 只能证明自洽，不能证明
语义。本目录的脚本把重建产物交给独立实现检验，并规定它们意见不一致时
听谁的。

## oracle 清单与作用

| oracle | 检验内容 | 接入点 |
| --- | --- | --- |
| 库内 reparse + integrity | 结构可再读、checksum/signature 自洽 | 单测 `DexRealCorpus.*`、`DexIncremental.*` |
| baksmali（dexlib2 2.5.2，版本钉死） | 反汇编文本等价：指令、try/catch、注解、调试信息 | `check.sh`（默认模式） |
| ReDex | 第二实现的读取-重写往返：libdex 输出能被 ReDex 读取、重写后仍被下游接受 | `check.sh`（`LIBDEX_ORACLE_MODE=redex`） |
| ART 实机（dex2oat/dexopt） | 终极消费者：verify/compile 接受，执行语义正确 | `check.sh`（`LIBDEX_ORACLE_MODE=art`） |
| AOSP dex-format 规范 | 结构争议时的文本依据 | 人工 + design.md 记录 |

## 仲裁顺序

意见一致时无事可做；不一致时按以下顺序裁决，并把裁决记录进 design.md
或对应测试注释：

1. **ART 实机为终审**。dex 的存在意义是被 ART 加载执行；baksmali/ReDex
   拒绝一份 ART 能正确执行的文件，按 dexlib2/ReDex 的解析缺陷记录，
   不改库的行为去迎合。反过来，ART 拒绝的文件无论哪个工具接受都算
   库的 bug。
2. **规范文本解决工具间的分歧**。两个用户态工具意见相左、ART 缺席时，
   以 AOSP dex-format 规范为准；规范自身含糊或滞后（如 map type 常量
   的勘误）时，按"现代实现共识"（d8 产物 + ART + dexlib2 三方一致）
   处理，并在 design.md 注明依据。
3. **语义不变是修复底线**。任何修复不得以"让某个工具闭嘴"为目标改变
   语义——布局可以调整，字节 diff 大小不是优化目标。

## 环境缺席的处理

`check.sh` 按 `LIBDEX_ORACLE_MODE` 分派；`redex`/`art` 模式在对应工具
（`redex` 可执行文件 / adb 与设备）缺席时**明确输出 skip 并以 0 退出**，
不伪装通过、也不阻塞流水线。CI 里 baksmali 模式是门槛，redex/art 是
增量信号。

## baksmali 输出的已知非语义差异

- 方法块顺序：canonical 重排 method_ids 后 class_data 顺序改变，方法块
  会换位。`check.sh` 对方法块排序后再 diff；字段/注解/指令文本仍逐字节。
- 行号表、debug 信息的文本投影随 `-a` API 级别变化，脚本固定
  `LIBDEX_ORACLE_API`（默认 30）。
