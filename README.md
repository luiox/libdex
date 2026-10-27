# libdex

> **Under Construction / 施工中** — API 与格式会变，尚未发布。

[![ci](https://github.com/luiox/libdex/actions/workflows/ci.yml/badge.svg)](https://github.com/luiox/libdex/actions/workflows/ci.yml)

DEX（Android 字节码）读写库。保真 DOM 加逐条目 codec，返回值与错误都走 `Result`；不定义方法体 AST，语义简化留给使用方 adapter。

## 能做什么

- 读取 035–041：header（含 041 container 字段）、ID 表、class_data、code_item、try/catch、注解、静态初值、debug_info、call_site/method_handle。
- 未修改写回原字节透传；`buildDex` 重新排布为 canonical 布局，回填偏移并重算 checksum/SHA-1；041 的 canonical 重建把 container 字段按独立文件约定重置为 `(file_size, 0)`。
- 增量布局：`BuildOptions::incremental` 保留源布局、未编辑条目源字节透传，只重编码被改条目（编辑不得触及 ID 表，详见 `doc/design.md`「增量重建」）。
- 方法体 CodeDom：`CodeUnit` 槽表 + `MethodEditor`（append/label/try/commit），值句柄引用指令槽；从零构建类与方法（`DexFile::createEmpty` + ID 表 intern 家族 + 成员注入），控制流与 payload 都可程序化生成。
- 指令与寄存器原语：const 取值域、索引上限、分支目标、地址重算；寄存器域读写（按格式校验 4/8/16 位）、批量平移/重映射、payload 构造器（packed/sparse-switch 与 fill-array-data，自包含存储）。
- 分析层：`buildCfg` 基本块图（流内边 + 异常边），`analyzeFrames` 逐指令到达帧——寄存器类型格（cat1/cat2 配对、引用带 type_idx、UninitRef 由 `<init>` 调用初始化）、move-result 配对、monitor 平衡；best-effort 与 strict 双档，strict 产出五类诊断（语料门保证真实 dex 零误报）。
- `vacuumIds`（显式 opt-in）：引用闭包收集后剔除不可达的 ID 表条目并全量重写引用（指令、debug、注解、encoded_value、class_data、call_site/method_handle），表长收缩、二次重建字节固定。
- smali 文本层（libsmali，仓内）：反汇编 `disassembleClass`/`disassembleAll`（baksmali 兼容文法，label 合成、注解与 debug 投影）与汇编 `SmaliAssembler::assembleClass`（label 解析、寄存器映射 pN→vN、形态选择）；往返在 035–039 真实语料上封闭。
- 按 method_idx 替换方法体，供反混淆、审计与重写使用。
- 追加或复用字符串（`internString`/`internUtf8`）；重建时按 UTF-16 重排字符串池并去重。
- 追加或复用 type/proto/field/method 条目（`addType`/`addProto`/`addField`/`addMethod`）；proto 可按参数列表直建（`addProtoWithParams`，shorty 自动推导）。
- 新建 type_list：`addTypeList` 入池去重，`setClassInterfaces` 覆盖类接口；重建时发射为新 type_list 并回填偏移。
- 往已有类注入字段/方法（`BuildOptions::fieldAdditions`/`methodAdditions`）：成员写进 class_data，新增方法体参与 code 布局；static_values 按新字段顺序重建，`setStaticFieldValue` 可给静态字段显式赋初值（宽度归一到最小，类别须匹配字段类型）。
- 新增类：向 `classDefs` 追加条目，再用成员注入填 class_data；接口列表用 `setClassInterfaces` 新建，注解与静态初值都有覆盖 API。
- 删除成员或类：`removedFields`/`removedMethods` 把成员移出 class_data（静态字段同时重建 static_values），类则直接从 `classDefs` erase；ID 表条目保留，被引用的条目变成外部引用。
- 覆盖成员 access_flags（`fieldAccessFlags`/`methodAccessFlags`）：方法可切换直接/虚方法分组；字段不能改 static 位。
- 剥离元数据：`stripDebugInfo` 丢弃全部 debug_info，`stripAnnotations` 丢弃注解族并清零 class_def 的 annotations_off。
- 新建/编辑注解：`addAnnotationItem` 入池去重，`setClassAnnotations`/`setFieldAnnotations`/`setMethodAnnotations`/`setParameterAnnotations` 按成员覆盖；重建时与源注解目录合并成生效目录后重新发射，未覆盖的成员沿用源条目。
- 重命名类型、字段或方法：重建时按 DEX 排序键重排五张 ID 表与 class_defs，重新编码 type_list，并同步重写 class_data、指令、catch、debug_info、注解与 encoded_value 中的全部索引。
- 指令与 encoded_value 精确编码：保留原始宽度与指令形态，不合并 `const` 变体。
- 未建模 map section 按原字节保留，可选择在重建时丢弃。

非空 link 区、APK/多 dex 容器与 compact dex（cdex/vdex）不在当前范围。索引移动而仍保留未建模 section 时，重建返回 `UnmappedRawSection`，需显式丢弃这些 section。

## 构建

```sh
xmake f --with_tests=y
xmake build libdex
xmake build dexbuild
xmake build smalict      # libsmali CLI：反汇编 / 汇编 / 往返自检
xmake run libdex_unittest --gtest_brief=1
```

其它工具 target（`--with_asan=y` 配合泄漏门）：`libdex_leak_check`（ASan
走查：读→全解码→帧分析→重建→重读）、`dexperf`（大文件性能基线计时）。

依赖经 xmake 自动拉取（libca / libjstr 来自 [luiox-repo](https://github.com/luiox/luiox-repo)）。Windows 需要 Visual Studio 2022；若 xmake 误选 mingw，显式 `xmake f -p windows --toolchain=msvc`。

## 测试与对拍

真实 dex 通过 `LIBDEX_REAL_DEX_DIR` 注入，不提交到仓库；变量缺席时相关测试 skip。

对拍用 baksmali 2.5.2：重建后分别反汇编原文与产物，smali 文本必须一致。canonical 重建会按规范重排 method_ids，class_data 的方法顺序随之变化，因此脚本按方法块排序后再比较（字段、注解与指令文本仍逐字节比较）。脚本会把固定版本 jar 拉到 `.oracle-cache/`，需要 Java 17+。

```sh
./build/<plat>/<arch>/release/dexbuild fixture /tmp/hello.dex
tools/oracle/check.sh /tmp/hello.dex
```

真实语料逐文件对拍：

```sh
for f in "$LIBDEX_REAL_DEX_DIR"/*.dex; do tools/oracle/check.sh "$f"; done
```

`check.sh` 另有两个环境依赖的 oracle 模式：`LIBDEX_ORACLE_MODE=redex` 让原文与重建产物走同一 ReDex 优化管线后反汇编比较（redex 可 `brew install redex` 或用 `LIBDEX_REDEX_BIN` 指定），`LIBDEX_ORACLE_MODE=art` 把两者推到 adb 设备由 dex2oat 验收（仲裁规则见 [tools/oracle/README.md](tools/oracle/README.md)）。对应工具缺席时明确 skip。

语料：`tools/corpus/gen_corpus.sh` 用本机 Android SDK 的 d8 生成 035–039 样本；040/041 由 root 可读设备提取（`tools/corpus/extract_art.sh`）。产物不入库，清单入库。

CI 在 Ubuntu 与 Windows 上跑单测和 fixture 对拍；Ubuntu 另跑 d8 语料上的 baksmali 对拍与 redex 对拍（观察期）。baksmali 通过不等于 ART 接受，最终以 AOSP 规范为准。

## 示例

```cpp
#include "dex/dex.hpp"

using namespace dex::core;

auto parsed = readDex(ByteSlice{bytes.data(), bytes.size()});
if (parsed.is_err()) return;
std::unique_ptr<DexFile> file = std::move(parsed).unwrap();

auto data = file->classData(0);
if (data.is_ok() && data.unwrap() != nullptr) {
    const EncodedMethod& method = data.unwrap()->directMethods[0];
    auto code = file->codeItem(method.codeOff);
    if (code.is_ok() && code.unwrap() != nullptr) {
        auto insns = decodeInsns(subOrEmpty(file->source(), code.unwrap()->insns.offset,
                                            code.unwrap()->insns.length));
    }
}

auto rebuilt = buildDex(*file);  // canonical 布局 + 校验字段重算
```

## 文档

- [doc/design.md](doc/design.md)：分层、契约与设计裁决。
- [doc/roadmap.md](doc/roadmap.md)：补齐路线——场景矩阵、M0–M5 里程碑与 goal 边界。
- [dev_plan.md](dev_plan.md)：当前能力、缺口与下一步（批次事实记账）。
- [CONTRIBUTING.md](CONTRIBUTING.md)：构建、语料、对拍与提交约定。

## License

MIT，见 [LICENSE](LICENSE)。
