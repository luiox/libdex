/// @file        error.hpp
/// @brief       读取/写出错误码、解析状态与诊断收集。
///
/// 与 libjbc core 同族的三条纪律：
///   - 解析失败用返回值（Result）而非异常抛出，恶意输入是预期输入；
///   - @ref ParseState 描述「这个模型还能做什么」，不把输入武断判成合法/非法；
///   - 诊断是解析产物的一部分，不是 stderr 副作用——调用方决定怎么处理。
#pragma once

#include <vector>

#include "libca/core/datatype.hpp"

namespace dex::core {

/// @brief 读取失败原因。
///
/// 结构性错误（无法确定后续边界）走 Err；语义性错误（索引悬垂、校验和不符）
/// 只记诊断并让模型进入 @ref ParseState::Recovered。
enum class ReadError {
    Ok = 0,
    Truncated,             ///< 字节不够读完一个结构
    BadMagic,              ///< 不是 dex\nNNN\0
    UnsupportedVersion,    ///< 版本号不在 035/037/038/039/040/041 之列
    BadHeaderSize,         ///< header_size 小于 0x70 或与版本约定不符
    BadEndianTag,          ///< endian_tag 不是 0x12345678（大端变体不支持）
    BadFileSize,           ///< header.file_size 与实际字节数不符（诊断）
    BadMapList,            ///< map_list 越界、条目数异常或与头部表计数不符
    BadTableSpan,          ///< ID 表/区间声明的 (size, off) 越出文件
    BadStringData,         ///< string_data_item 越界、无终止 NUL 或 ULEB 非法
    BadLeb128,             ///< LEB128 编码超过 32 位或字节数超限
    BadClassData,          ///< class_data_item 的计数/差分/索引非法
    BadCodeItem,           ///< code_item 头部、指令区或 tries 区越界/自相矛盾
    BadIndex,              ///< 索引悬垂或指向错误类型的条目（诊断）
    BadChecksum,           ///< adler32 校验和不符（诊断）
    BadSignature,          ///< SHA-1 签名不符（诊断）
};

/// @brief 写出失败原因。
///
/// 只读核阶段只有未修改透传路径；重编码错误面（Unencodable/NotModeled）随
/// 编辑写回阶段落地。
enum class WriteError {
    Ok = 0,
    MissingSource,  ///< 需要源字节但模型未保留
};

/// @brief 模型的解析状态：描述能力，而非合法性。
///
/// - Validated：骨架与可见引用通过校验，没有已知的不合规区段；
/// - Recovered：主体可读，但存在「结构可确定、语义不合规」的区段（校验和不符、
///   悬垂索引、map 计数不符等），降级事实记录在 @ref Diagnostics 里，模型仍可
///   原样写回。
///
/// 结构损坏（边界无法确定）不走本枚举：reader 阶段一律 Err，不产出半截模型。
enum class ParseState {
    Validated,
    Recovered,
};

/// @brief 错误码的可读文本（诊断输出用）。
const char* to_string(ReadError e) noexcept;

/// @brief 错误码的可读文本（诊断输出用）。
const char* to_string(WriteError e) noexcept;

/// @brief 解析状态的文本标签（测试断言与诊断输出用）。
const char* to_string(ParseState s) noexcept;

/// @brief 单条诊断：降级/异常的可检索记录。
struct Diagnostic
{
    enum class Level : ca::u8 { Note = 0, Warning = 1, Error = 2 };

    Level level = Level::Note;
    ReadError code = ReadError::Ok;
    ca::u32 offset = 0;  ///< 记录发生位置，便于回溯到源字节

    static Diagnostic note(ReadError c, ca::u32 off) noexcept
    {
        return Diagnostic{Level::Note, c, off};
    }
    static Diagnostic warning(ReadError c, ca::u32 off) noexcept
    {
        return Diagnostic{Level::Warning, c, off};
    }
    static Diagnostic error(ReadError c, ca::u32 off) noexcept
    {
        return Diagnostic{Level::Error, c, off};
    }

    bool isError() const noexcept { return level == Level::Error; }
};

/// @brief 诊断收集器：解析过程中的降级记录，非空不代表解析失败。
class Diagnostics
{
public:
    void add(Diagnostic d) { items_.push_back(d); }
    void note(ReadError c, ca::u32 off) { add(Diagnostic::note(c, off)); }
    void warn(ReadError c, ca::u32 off) { add(Diagnostic::warning(c, off)); }
    void error(ReadError c, ca::u32 off) { add(Diagnostic::error(c, off)); }

    bool empty() const noexcept { return items_.empty(); }
    ca::usize count() const noexcept { return items_.size(); }
    const std::vector<Diagnostic>& items() const noexcept { return items_; }

    /// @brief 是否存在 Error 级诊断（Warning 级表示已降级但结果可用）。
    bool hasError() const noexcept
    {
        for (const Diagnostic& d : items_) {
            if (d.isError()) {
                return true;
            }
        }
        return false;
    }

    /// @brief 是否记录了指定错误码（测试与上层策略用）。
    bool contains(ReadError code) const noexcept
    {
        for (const Diagnostic& d : items_) {
            if (d.code == code) {
                return true;
            }
        }
        return false;
    }

private:
    std::vector<Diagnostic> items_;
};

}   // namespace dex::core
