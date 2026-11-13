.. _oracle:

对拍体系
========

状态：定稿。重建正确性的外部仲裁链与语料纪律；工具面用法见 ``tools/oracle/README.md``。

文本对拍（baksmali）
--------------------

文本 oracle 是 baksmali 2.5.2（dexlib2）：原文件与 ``buildDex`` 产物分别反汇编，smali 文本必须一致。canonical 重建按规范重排 method_ids 后，class_data 的方法顺序会变；方法块顺序不是语义，脚本按块排序后再 diff，字段、注解与指令文本仍逐字节比较。它覆盖指令、try/catch、注解、静态初值、debug 行号与访问标志。

仲裁规则
--------

baksmali 不覆盖未建模 section，也不等于 ART 接受。仲裁规则（ART 终审、规范裁决工具分歧、环境缺席明确 skip）见 ``tools/oracle/README.md``；``check.sh`` 按 ``LIBDEX_ORACLE_MODE`` 分派 baksmali/redex/art 三种模式，redex 与 art 在对应工具缺席时明确 skip。

redex 模式是双边管线对比：原文与重建产物走同一 ReDex 优化管线，管线自身的改写（内联、DCE 等）对两侧等价生效而抵消，两侧产物反汇编后必须一致，单边对比会被管线自身改写污染。CI（Linux）用 Homebrew bottle 装 redex，并用 runner 预装 Android SDK 的 d8 生成语料跑 baksmali/redex 对拍；art 的常驻设备配方见 oracle README。

语料纪律
--------

真实语料不入库，通过 ``LIBDEX_REAL_DEX_DIR`` 注入；第三方 APK 只允许哈希清单与复现脚本。040/041 由设备提取（``tools/corpus/extract_art.sh``）。
