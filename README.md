# libdex

> **Under Construction / 施工中** — API 与格式会变，尚未发布。

[![ci](https://github.com/luiox/libdex/actions/workflows/ci.yml/badge.svg)](https://github.com/luiox/libdex/actions/workflows/ci.yml)

DEX（Android 字节码）读写库。保真 DOM 加逐条目 codec，返回值与错误都走 `Result`；不定义方法体 AST，语义简化留给使用方 adapter。

## 能做什么

- 读取 035–041：header、ID 表、class_data、code_item、try/catch、注解、静态初值、debug_info、call_site/method_handle。
- 未修改写回原字节透传；`buildDex` 重新排布为 canonical 布局，回填偏移并重算 checksum/SHA-1。
- 按 method_idx 替换方法体，供反混淆、审计与重写使用。
- 指令与 encoded_value 精确编码：保留原始宽度与指令形态，不合并 `const` 变体。
- 未建模 map section 按原字节保留，可选择在重建时丢弃。

041 的 container 字段只解析不重建；非空 link 区、APK 容器与 smali 文本层不在当前范围。

## 构建

```sh
xmake f --with_tests=y
xmake build libdex
xmake build dexbuild
xmake run libdex_unittest --gtest_brief=1
```

依赖经 xmake 自动拉取（libca / libjstr 来自 [luiox-repo](https://github.com/luiox/luiox-repo)）。Windows 需要 Visual Studio 2022；若 xmake 误选 mingw，显式 `xmake f -p windows --toolchain=msvc`。

## 测试与对拍

真实 dex 通过 `LIBDEX_REAL_DEX_DIR` 注入，不提交到仓库；变量缺席时相关测试 skip。

对拍用 baksmali 2.5.2：重建后分别反汇编原文与产物，smali 文本必须一致。脚本会把固定版本 jar 拉到 `.oracle-cache/`，需要 Java 17+。

```sh
./build/<plat>/<arch>/release/dexbuild fixture /tmp/hello.dex
tools/oracle/check.sh /tmp/hello.dex
```

真实语料逐文件对拍：

```sh
for f in "$LIBDEX_REAL_DEX_DIR"/*.dex; do tools/oracle/check.sh "$f"; done
```

CI 在 Ubuntu 与 Windows 上跑单测和 fixture 对拍。baksmali 通过不等于 ART 接受，最终以 AOSP 规范为准。

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
- [dev_plan.md](dev_plan.md)：当前能力、缺口与下一步。
- [CONTRIBUTING.md](CONTRIBUTING.md)：构建、语料、对拍与提交约定。

## License

MIT，见 [LICENSE](LICENSE)。
