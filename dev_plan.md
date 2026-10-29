# dev_plan

libdex 的剩余工作。契约与裁决见 doc/design.md，范围外清单见 doc/non_goals.md。

## 剩余工作

- redex 双边对比从未实机跑过：CI 的 Ubuntu runner 无 brew，redex 步骤一直在 skip，观察期实际未开始。需要能装 redex 的环境（brew / 自建二进制配 `LIBDEX_REDEX_BIN`）在语料上实机验证一轮，再决定是否转门禁。
- ART 实机 oracle 与 040/041 实物语料待常驻设备：提取脚本就绪（`tools/corpus/extract_art.sh`）；041 canonical 写回语义已冻结（独立文件约定），增量路径在实物复核前保持 `NotModeled`；040 与 039 的结构差异、041 container 字段在独立文件与容器内两种形态的取值，均待实物核对。
- type/proto/field/method 的 add* 去重是线性扫描（字符串已有哈希 intern 索引）：6.4 万方法时生成侧 O(n²) 可感（~7s），读/重建路径不受影响；哈希去重索引是唯一记录在案的优化项。
- 结构整改分期：① insn.hpp 拆出指令编辑原语（数据模型与 adapter 原语分离）；② opcode 分类单源（core 的 kOpcodes 收编 smali 名称表与 analysis 形状判别，加 opcode 只改一处）；③ DexFile 状态分组（自有池/懒解码缓存/编辑层子对象化，公开 API 不变）；④ smali 对 CodeDomError 的映射改穷举 switch（新增枚举值编译期报错）；⑤ MethodEditor 扩为方法体中层编辑 API（try/handler/debug/payload 高层操作），assemble.cpp 收敛到中层。canonical/incremental 两条布局策略保持分离（保真契约不同），字节原语与 header 常量已单源（bytes.hpp / format.hpp）。
