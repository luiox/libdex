# libdex 不做清单

范围外事项与对应裁决。裁决变化先改这里，再动代码。

- odex / vdex / art / compact dex（cdex）。
- APK、resources.arsc、AXML、classes2.dex 与多 dex 模型；跨文件全局索引归上层。
- 增量路径的 ID 表级新增与删除：intern/addType/addMethod 等触及 ID 表即 `NotIncremental`，改走 canonical；vacuum 仅作为 canonical 路径的显式 opt-in（`BuildOptions::vacuumIds`）。
- visitor 形状；方法体 AST 归 CodeDom（值句柄、无 visitor，见 design「分层」）。
- opcode 形态合并或自动提升：core 按调用方给定的 opcode 精确编码，形态选择归 adapter（libsmali 汇编器）。
- 修改后字节 diff 最小化：增量重建保留源布局，diff 小是布局保持的结果而非优化目标；不提供字节级 patch。
- 非空 link 区：重建返回 `NotModeled`。
