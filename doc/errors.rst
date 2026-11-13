.. _errors:

错误码与诊断契约
================

状态：定稿。错误通道的分档与逐码语义；读入分档（eager/lazy）见 :ref:`architecture-eager-lazy`。

错误通道
--------

错误走 ``Result``，不抛异常。结构性问题返回 Err；语义问题（校验和不符、悬垂索引、map 计数不符）记诊断并将 ``ParseState`` 置 ``Recovered``，模型仍可读（error 头注）。

``ParseState`` 只有 ``Validated`` 与 ``Recovered``；结构损坏不产出半截模型。

指令编码错误单独走 ``InsnEncodeError``\（``BadFormat`` / ``OperandOverflow`` / ``BadPayload`` / ``MisalignedPayload``），语义见 :ref:`insns-codec`。

.. _errors-read:

ReadError 逐码语义
------------------

错误码分四档：读入被拒、带病可读、延迟到访问、构建期。

.. list-table::
   :header-rows: 1

   * - 码
     - 档
     - 语义
     - 覆盖测试
   * - ``Truncated``
     - 硬拒
     - 字节不够读完一个结构（header/表项中间截断）
     - malformed
   * - ``BadMagic``
     - 硬拒
     - magic 不是 ``dex\nNNN\0``
     - malformed
   * - ``UnsupportedVersion``
     - 硬拒
     - 版本号不在 035–041 之列
     - malformed
   * - ``BadHeaderSize``
     - 硬拒/降级
     - ``< 0x70`` 硬拒；``!=`` 版本约定（041 应为 0x78）记诊断
     - malformed
   * - ``BadEndianTag``
     - 硬拒
     - endian_tag 不是 0x12345678（大端变体不支持）
     - malformed
   * - ``BadFileSize``
     - 降级
     - header.file_size 与实际字节数不符
     - real_corpus
   * - ``BadMapList``
     - 降级/硬拒
     - map_list 越界或与头部表计数不符（偏移越界可恢复）
     - malformed
   * - ``BadTableSpan``
     - 硬拒
     - ID 表/区间声明的 (size, off) 越出文件
     - malformed
   * - ``BadStringData``
     - 访问时
     - string_data_item 越界、无终止 NUL 或 ULEB 非法（``string()``/``stringData()`` 时报）
     - lazy
   * - ``BadLeb128``
     - 访问时
     - LEB128 超过 32 位或字节数超限
     - leb128
   * - ``BadClassData``
     - 访问时/硬拒
     - 偏移悬垂降级；payload 计数/差分非法则 fail-closed
     - malformed/lazy
   * - ``BadCodeItem``
     - 访问时
     - code_item 头部、指令区或 tries 区越界/自相矛盾
     - code_item
   * - ``BadEncodedValue``
     - 访问时
     - encoded_value 类型、value_arg 或嵌套深度非法
     - encoded_value
   * - ``BadIndex``
     - 降级
     - 索引悬垂或指向错误类型的条目（解码条目时记诊断）
     - code_item
   * - ``BadChecksum``
     - 降级
     - adler32 不符（可 ``verifyIntegrity(false)`` 关闭）
     - malformed
   * - ``BadSignature``
     - 降级
     - SHA-1 签名不符（同上）
     - malformed
   * - ``IdTableFull``
     - 构建期
     - type/proto/field/method 表达到 65536 条上限（格式硬顶）
     - builder

.. _errors-write:

WriteError 逐码语义
-------------------

.. list-table::
   :header-rows: 1

   * - 码
     - 语义
     - 覆盖测试
   * - ``MissingSource``
     - 需要源字节但模型未保留（无源走增量/透传）
     - incremental
   * - ``Unencodable``
     - 模型内容超出编码域宽或自相矛盾，拒绝产出截断字节
     - class_data
   * - ``NotModeled``
     - 版本或结构没有冻结语义（增量路径的 041、非空 link 区、大端）
     - version041
   * - ``SourceUnreadable``
     - 重建需要再次解码源条目，但源字节不可读或自相矛盾
     - builder
   * - ``InvalidModel``
     - 模型引用缺失或替换项指向不存在/无方法体的方法
     - builder_edit
   * - ``UnmappedRawSection``
     - 表索引需要重排，但未建模 section 无法迁移内部引用
     - builder
   * - ``NotIncremental``
     - 增量重建的前提被破坏（编辑触及 ID 表），需改走 canonical
     - incremental
