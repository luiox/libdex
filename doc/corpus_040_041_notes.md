# 040/041 语料与 container 语义笔记

状态：提取路径就绪（`tools/corpus/extract_art.sh`，假设备 shim 端到端
验证），**实物语料待常驻设备产出**。未在实物上核对的说法显式标注。

## 为什么 d8 造不出 040/041

- 035–039 由 `d8 --min-api` 生成（`tools/corpus/gen_corpus.sh`），d8 的
  产出上限就是 039。
- 040：标准 dex 的 magic 版本串进到 `dex\n040\0`，只有设备侧 ART 在
  dexopt 流程里写。与 039 的结构差异点**待实物核对**：header 是否扩位、
  map 是否新增 type。
- 041：两类形态——
  1. 标准 dex 头新增 container 字段（`container_size` / `header_offset`，
     magic `dex\n041\0`）；
  2. compact dex（magic `cdex0015`），vdex 容器内的常驻形态。

## 提取路径

`extract_art.sh`：adb root 可读的设备上枚举 `/data/dalvik-cache` 与
`/data/app` 下的 vdex/cdex → 拉取 → 扫描内嵌 magic → 按段自身 header 的
`file_size`（+32 处 u32）切出 → 按 magic 分类为 040/041/cdex → 产出
SHA-256 清单与带设备指纹的报告。产物不入库；清单与报告入库（同
gen_corpus 纪律）。

## 041 container 字段语义（写回裁决已冻结，实物待复核）

- 标准 dex 041：header 尾部两个 u32——`container_size`（整个容器文件
  大小）、`header_offset`（本 dex header 在容器中的偏移）；独立文件时
  约定 `container_size == file_size`、`header_offset == 0`。
- cdex0015：header 布局与标准 dex 不同（含 quickening 信息，数据区排布
  独立）；libdex 明确不做 compact dex（design.md「不做」）。
- 对 libdex 的语义（已实现，实物到位时按 ART oracle 复核）：
  - 读：041 标准 dex 的 container 字段作为 header 一部分透传；
  - 写：canonical 重建输出单文件，container 字段重置为
    `(file_size, 0)`（独立文件约定；canonical 产物不继承容器上下文，
    version041_test 背书）；增量路径保持 `NotModeled`（041 布局未经
    实物验证前不承诺字节恒等）；
  - 不做：vdex/cdex 容器解析与 cdex 重编码仍归库外。

## 验收清单（实物到手时）

1. `extract_art.sh` 真机跑通，`manifest_art.sha256` 与 `LIBDEX_REAL_DEX_DIR`
   注入后的 reparse 测试全绿。
2. 核对 040 与 039 的结构差异，回填本文与 design.md。
3. 核对 041 标准 dex 的 container 字段取值（独立文件与容器内各一份）。
4. ART oracle（`LIBDEX_ORACLE_MODE=art`）在 040/041 语料上跑通。

## 相关

- [oracle 仲裁规则](../tools/oracle/README.md)
- [design](design.md)：单文件职责与「不做」清单。
