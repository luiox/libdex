# dev_plan

libdex 的剩余工作。契约与裁决见 doc/design.md，范围外清单见 doc/non_goals.md。

## 剩余工作

- redex 双边对比从未实机跑过：CI 的 Ubuntu runner 无 brew，redex 步骤一直在 skip，观察期实际未开始。需要能装 redex 的环境（brew / 自建二进制配 `LIBDEX_REDEX_BIN`）在语料上实机验证一轮，再决定是否转门禁。
- ART 实机 oracle 与 040/041 实物语料待常驻设备：提取脚本就绪（`tools/corpus/extract_art.sh`）；041 canonical 写回语义已冻结（独立文件约定），增量路径在实物复核前保持 `NotModeled`；040 与 039 的结构差异、041 container 字段在独立文件与容器内两种形态的取值，均待实物核对。
