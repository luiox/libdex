# libdex

> **Under Construction / 施工中** — API、文件布局与错误码都会变，尚未发布。当前状态见 [dev_plan.md](dev_plan.md)。

[![ci](https://github.com/luiox/libdex/actions/workflows/ci.yml/badge.svg)](https://github.com/luiox/libdex/actions/workflows/ci.yml)

DEX 字节核（L1）的 C++ 建模库，契约与 libjbc core 同族：

- **core**：单 DexFile lazy DOM——header、map_list、五张全局 ID 表、class_defs、call_site_id/method_handle 骨架 eager；string_data、class_data、code_item/异常处理器、type_list、注解族、编码数组与 debug_info 按需解码；未建模 map section 保留原始区间；未修改写回原字节透传。
- **builder**：`buildDex` 做 canonical 整文件重建——按依赖顺序重排数据区、回填 string_data/type_list/class_data/code/注解偏移、重建 map_list、重算 checksum 与 SHA-1；方法体可按 method_idx 替换。
- **value**：encoded_value/encoded_annotation 全类型解码，保留原始 `value_arg`；重编码按所记宽度写回，解码→编码字节一致。
- **insn**：code_item.insns 的指令 DOM 与精确编码器——操作码/格式元数据、全格式操作数解码、payload 零拷贝视图、逐 opcode 的定长编码（不合并 const 形态）。
- **type**：DEX 字段类型与方法描述符解析。
- **integrity**：adler32 checksum 与 SHA-1 signature 的核对与重算工具。

设计取向：模型是数据，读写是行为——visitor 事件协议不进公共 API；错误走 `Result` 值语义，不抛异常；未修改字节级往返是硬门禁，写回不是 sanitizer。库只提供保真 DOM 与逐条目 codec，不提供方法体 AST；简化与语义合并由使用方的 adapter 完成。

## 当前状态

开发中，未发布。`0.0.1` 只是构建占位版本，不代表发布基线；主线仍是原型提交。

已实现：035–041 解析、全方法体指令解码与精确重编码、class_data/code_item 的整条目重编码、try/catch 处理器、类型/方法描述符、注解族与静态初值、debug_info 状态机、call_site/method_handle、未知 map section 保留、值编码往返、未修改字节往返，以及 `buildDex` 的 canonical 整文件重建与方法体替换；041 的 container 语义未冻结，builder 明确拒绝。baksmali 文本对拍已接入 CI，但还没有 APK 端到端验证与 ART 实机验证；尚未接线：ReDex 写回参照、条目级 dirty 状态、ID 表追加护栏、smali 文本层与 APK 容器语义。设计与裁决见 [doc_ai/design.md](doc_ai/design.md)，实现账目见 [dev_plan.md](dev_plan.md)。

## 构建

依赖经 xmake 自动拉取（libca / libjstr 来自 [luiox-repo](https://github.com/luiox/luiox-repo)，gtest 来自 xrepo）：

```sh
xmake f --with_tests=y
xmake build libdex
xmake build libdex_unittest
xmake build dexbuild
xmake run libdex_unittest --gtest_brief=1
```

只构建库本体：`xmake f --with_tests=n`。Windows 下若 xmake 误选 mingw，显式指定 `xmake f -p windows --toolchain=msvc`，并确保 Visual Studio 2022 的 C++ 工具链可用。

## 测试语料

合成 035 fixture 在测试内构造，覆盖骨架解析、懒解码、指令格式与 payload、try/handler、描述符、注解族、值编码、debug_info、call_site/method_handle、未知 map section、class_data/code_item 重编码、整文件重建与方法体替换、畸形输入与字节级往返。真实语料经 `LIBDEX_REAL_DEX_DIR` 注入一个存放 `.dex` 的目录；有语料时额外解码每个方法体并逐字节重编码比对，核对指令宽度和、31t 引用的 payload 类型与 switch case 目标，遍历全部注解目录与参数 set，对静态初值数组、annotation_item、class_data_item、code_item 以及存在的 debug_info 做解码→重编码字节比较，并对整份文件做 canonical 重建：重读为 Validated、完整性字段有效、逐方法指令字节一致、新注解与静态初值偏移可解、二次重建字节稳定；变量缺席或目录为空时对应测试 skip，不硬失败。真实语料不入库，第三方 APK 本体不提交。

## 对拍

语义对拍用 baksmali 2.5.2（dexlib2）：先用 `dexbuild rebuild` 重建 dex，再分别反汇编原文与产物，要求两份 smali 文本完全一致。对拍覆盖指令、try/catch、注解、静态初值、debug 行号与局部变量、访问标志与类层次；未建模 section 不在 baksmali 文本面内，由单测的 raw 保留用例覆盖。

```sh
xmake build dexbuild
./build/<plat>/<arch>/release/dexbuild fixture /tmp/hello.dex
tools/oracle/check.sh /tmp/hello.dex          # Linux/macOS
bash tools/oracle/check.sh /tmp/hello.dex     # Windows Git Bash
```

脚本从 Maven Central 拉取固定版本 jar 到 `.oracle-cache/`，需要 Java 17+。真实语料逐文件对拍：

```sh
for f in "$LIBDEX_REAL_DEX_DIR"/*.dex; do tools/oracle/check.sh "$f"; done
```

baksmali 只证明 dexlib2 能解析且文本语义一致，不等于 ART 接受；oracle 与 AOSP DEX 规范冲突时以规范为准。CI 在 Linux 与 Windows 上跑合成 fixture 的对拍，真实语料因体积与授权不提交。

## 最小示例

```cpp
#include "dex/dex.hpp"

using namespace dex::core;

auto r = readDex(ByteSlice{bytes.data(), bytes.size()});
if (r.is_err()) return;                 // 错误即值，不抛异常
auto rr = std::move(r).unwrap();
DexFile& file = *rr;

auto name = file.classDescriptor(0);    // lazy：type_id → string_data
if (name.is_ok()) use(name.unwrap().as_std_view());

auto data = file.classData(0);          // lazy：class_data_item
if (data.is_ok() && data.unwrap() != nullptr) {
    const EncodedMethod& m = data.unwrap()->directMethods[0];
    auto code = file.codeItem(m.codeOff);   // lazy：code_item 目录
    if (code.is_ok() && code.unwrap() != nullptr) {
        const ByteSpan span = code.unwrap()->insns;
        auto insns = decodeInsns(subOrEmpty(file.source(), span.offset, span.length));
        if (insns.is_ok()) {
            use_insns(insns.unwrap());
            auto codeBytes = encodeInsns(insns.unwrap());  // 未修改时逐字节还原
        }
    }
}

auto w = writeDex(file);                // 未修改 → 原字节透传

BuildOptions options;                   // codeReplacements 可按 method_idx 替换方法体
auto rebuilt = buildDex(file, options); // canonical 重排 + 校验字段重算
```

## License

MIT（见 [LICENSE](LICENSE)）。
