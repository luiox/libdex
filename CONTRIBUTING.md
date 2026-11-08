# Contributing

libdex 处于施工中（Under Construction）：API、文件布局与错误码会变，提交前先跑完整门禁。改动应保持分层边界：保真 DOM 与逐条目 codec 是底座，方法体编辑走 CodeDom（值句柄 + label），CFG 由分析层从指令流派生，DEX 与 smali 文本互转归仓内 libsmali；不引入 visitor 与方法体 AST。细节见分模块规格，自 [doc/module-map.rst](doc/module-map.rst) 按域进入。

## 构建与测试

```sh
xmake f -y --with_tests=y
xmake build libdex_unittest
xmake build dexbuild
xmake run libdex_unittest --gtest_brief=1
```

Windows 下需要 Visual Studio 2022 的 C++ 工具链；若 xmake 误选 mingw，显式 `xmake f -p windows --toolchain=msvc`。Linux 需要 g++ 与 pthread。

## 语料

合成 fixture 在 `test/unittest/dex_fixture.cpp` 内构造，必须保持确定性。真实 dex 通过 `LIBDEX_REAL_DEX_DIR` 注入，不提交 APK、dex 或反编译产物；需要引用第三方样本时只提交哈希清单与下载/复现脚本。

## 对拍

对拍脚本在 `tools/oracle/check.sh`，用 baksmali 2.5.2 比较原文与重建产物的 smali 文本。脚本自动从 Maven Central 拉取固定版本 jar 到 `.oracle-cache/`（已 gitignore），需要 Java 17+。

```sh
xmake build dexbuild
./build/<plat>/<arch>/release/dexbuild fixture /tmp/hello.dex
tools/oracle/check.sh /tmp/hello.dex
```

提交修复前至少跑一次真实语料的逐文件对拍：

```sh
for f in "$LIBDEX_REAL_DEX_DIR"/*.dex; do tools/oracle/check.sh "$f"; done
```

baksmali 文本对拍不等于 ART 接受；涉及布局、对齐或未建模 section 的改动，需要在说明里写清未验证部分。

## 代码约定

- 错误走 `Result` 值语义，不抛异常；库内禁用 RTTI。
- 公开类型用 `ca::i32`/`ca::u32`/`ca::usize`，字符串视图用 `std::string_view`，不新增 `std::string` 存储。
- 头注释用 `///`，不用 `/** */`；模块内 include `"file.hpp"`，跨模块 `"module/path/file.hpp"`，不用 `../`。
- 不改写用户数据：未修改写回原字节透传；重建走 `buildDex`（默认 canonical，或用 `BuildOptions::incremental` 显式选择增量布局）。
- 新增行为必须带测试；真实语料修复要加合成回归用例。

## 提交

提交标题直接说清改动，一条提交一件事；正文只写非显然的原因与验证结果。提交前 `git status`，不要带入 `build/`、`.oracle-cache/` 或本地语料。

## 许可

提交即表示同意以 MIT 许可发布，见 [LICENSE](LICENSE)。

## 文档规范

三层按**权威来源**分工，扩展名即角色：

| 载体 | 层 | 写什么 | 谁能引用它 |
|---|---|---|---|
| `///` Doxygen | 微观 | 单个符号的契约：参数、返回、失败模式、不变量；单模块的「背景/定位」（`@defgroup` 组注） | 随代码移动 |
| `doc/*.rst` | 宏观 | 跨模块设计、数据模型、增量重建与对拍契约 | 代码/测试/构建脚本 |
| `*.md` | 人 + AI 方向 | README、CONTRIBUTING、dev_plan 等流程文档 | 只有人和 AI 读 |

理由：markdown 撑不住代码耦合的规格——无 label、无校验引用面，代码改动后引用静默腐烂。RST 白送可校验的引用面，规范才谈得上执行。

硬规则（`doc/check_refs.py` + Sphinx `-W` 在 CI 挡）：

1. 代码/测试/工具脚本只可引用 `doc/*.rst`，路径必须存在；出现 `.md` 设计引用即失败（流程文档白名单除外）。
2. 引用定位用 label，形式 `doc:<label>`；被引用的位置必须有 `.. _<label>:` 声明（不必每节都放），命名 `<doc-slug>[-<section-slug>]`。跨文档的 `§N` 一律换 `:ref:`，编号会随插入章节漂移。
3. RST 里「`X` 头注」指向微观层：`X` 必须是某个 `@defgroup` 组名或头文件名。
4. RST 站点以 `sphinx-build -b html -E -W --keep-going doc doc/_build` 构建，警告即失败；本地验证先 `pip install "sphinx==9.1.1"`（与 CI 钉同版）。
5. 微观层以 `doxygen doc/Doxyfile` 构建，`WARN_AS_ERROR` 生效；`///` 注释是 API 契约的唯一来源，与代码同仓同改。

RST 写作约定（中文正文的坑）：表格一律 `.. list-table::`（禁 grid table，全角字形会破坏边框校验）；行内代码紧邻中文或全角开括号时在闭定界符后补转义（docutils 要求 end-string 后接空白或 ASCII 标点）；标题层级 `=` / `-` / `^`；跨仓出处带仓名标记（libca / libjstr / luiox），带标记视为 prose 不校验存在性。
