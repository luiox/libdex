# libdex

> **Under Construction / 施工中** — API 与格式会变，尚未发布。

[![ci](https://github.com/luiox/libdex/actions/workflows/ci.yml/badge.svg)](https://github.com/luiox/libdex/actions/workflows/ci.yml)

DEX（Android 字节码）单文件读写库。保真 DOM 加逐条目 codec，返回值与错误都走 `Result`；不定义方法体 AST，语义简化留给使用方 adapter。

- 读：035–041 全条目，未建模 section 原字节保留。
- 写：未修改逐字节透传；canonical 重建与增量布局两条写回路径，校验字段自动重算。
- 编辑：成员增删改、改名与索引重排、注解与静态初值、方法体 CodeDom（插删指令、控制流）、ID 表 vacuum、从零构建。
- 分析：基本块 CFG 与逐指令到达帧，best-effort / strict 双档。
- 文本：smali 反汇编与汇编（仓内 libsmali），往返封闭。

范围外（APK/多 dex、cdex/vdex、字节级 patch 等）见 [doc/non_goals.md](doc/non_goals.md)。

## 构建

```sh
xmake f --with_tests=y
xmake build libdex
xmake build dexbuild
xmake build smalict      # libsmali CLI：反汇编 / 汇编 / 往返自检
xmake run libdex_unittest --gtest_brief=1
```

`smalict` 三个子命令：`dis <file.dex> <out-dir>` 每类输出一个 `.smali`；`asm <smali-dir> <out.dex>` 把目录内 `*.smali` 汇编成一份 dex；`roundtrip <file.dex> <tmp-dir>` 走反汇编→汇编→重读→再反汇编，要求文本逐字节一致。

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
- [doc/non_goals.md](doc/non_goals.md)：不做清单。
- [dev_plan.md](dev_plan.md)：剩余工作。
- [CONTRIBUTING.md](CONTRIBUTING.md)：构建、语料、对拍与提交约定。

## License

MIT，见 [LICENSE](LICENSE)。
