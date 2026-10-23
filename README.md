# libdex

DEX 字节核（L1）的 C++ 建模库，契约与 libjbc core 同族：

- **core**：单 DexFile lazy DOM——header、map_list、五张全局 ID 表、class_defs 骨架 eager；string_data、class_data、code_item/异常处理器、type_list 按需解码；未修改写回原字节透传。
- **insn**：code_item.insns 的指令 DOM——操作码/格式元数据、全格式操作数解码、packed-switch/sparse-switch/fill-array-data payload 零拷贝视图。
- **type**：DEX 字段类型与方法描述符解析。
- **ir**：方法体只读 CodeDom——指令、label 边界、try 区域与结构问题。
- **integrity**：adler32 checksum 与 SHA-1 signature 的核对与重算工具。

设计取向：模型是数据，读写是行为——visitor 事件协议不进公共 API；错误走 `Result` 值语义，不抛异常；未修改字节级往返是硬门禁，写回不是 sanitizer。

## 当前状态

开发中，未发布。`0.0.1` 只是构建占位版本，不代表发布基线；仓内还没有首个提交。

当前只有自证测试，没有 dexlib2/baksmali 对拍、没有 APK 端到端验证，不能按“可用”计。已实现的范围是 035–041 解析、全方法体指令解码、try/catch 处理器、类型/方法描述符、只读 CodeDom 与未修改字节往返；注解、debug_info、静态初值、call site/method handle、重编码写回、builder 与 smali 文本层都还没有。设计与裁决见 [doc_ai/design.md](doc_ai/design.md)，实现账目见 [dev_plan.md](dev_plan.md)。

## 构建

依赖经 xmake 自动拉取（libca / libjstr 来自 [luiox-repo](https://github.com/luiox/luiox-repo)，gtest 来自 xrepo）：

```sh
xmake f --with_tests=y
xmake build libdex
xmake build libdex_unittest
xmake run libdex_unittest --gtest_brief=1
```

只构建库本体：`xmake f --with_tests=n`。Windows 下若 xmake 误选 mingw，显式指定 `xmake f -p windows --toolchain=msvc`，并确保 Visual Studio 2022 的 C++ 工具链可用。

## 测试语料

合成 035 fixture 在测试内构造，覆盖骨架解析、懒解码、指令格式与 payload、try/handler、描述符、CodeDom、畸形输入与字节级往返。真实语料经 `LIBDEX_REAL_DEX_DIR` 注入一个存放 `.dex` 的目录；有语料时额外解码每个方法体并构建 CodeDom，核对指令宽度和、31t 引用的 payload 类型与 switch case 目标；变量缺席或目录为空时对应测试 skip，不硬失败。真实语料不入库，第三方 APK 本体不提交。

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
        if (insns.is_ok()) use_insns(insns.unwrap());
    }
}

auto w = writeDex(file);                // 未修改 → 原字节透传
```

## License

MIT（见 [LICENSE](LICENSE)）。
