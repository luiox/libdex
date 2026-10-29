/// @file        bytes.hpp
/// @brief       源字节区段、视图助手与基于 libca Bytes 的随机访问读取器。
///
/// 字节原语全部复用 libca 的 Bytes 家族：`Bytes` 持有源字节并提供小端
/// `get_u16_le`/`get_u32_le`，`ByteSlice` 是非拥有视图，重编码写回用
/// `BytesMut`。libca 的 Bytes 只能从当前游标顺序读、`slice()` 越界抛异常，
/// 而 DEX 解析需要从任意 offset 开始；这里的 @ref Reader 只做两件事：
/// 在 offset 处切出一个 `Bytes` 视图，并把 `BytesError` 映射为 `ReadError`。
/// 所有错误仍走 Result，绝不用异常表达输入截断。
#pragma once

#include <utility>
#include <vector>

#include "libca/core/bytes.hpp"
#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"

#include "dex/error.hpp"

namespace dex::core {

// 本层所有错误通道都是 ca::core::Result；显式引入而非 using namespace。
using ca::core::ByteSlice;
using ca::core::Err;
using ca::core::Ok;
using ca::core::Result;

/// @brief 源字节流中的一段：lazy 与保真的共同载体。
struct ByteSpan
{
    ca::u32 offset = 0;
    ca::u32 length = 0;

    bool empty() const noexcept { return length == 0; }
};

/// @brief [offset, offset+length) 是否完全落在视图内。
inline bool covers(ByteSlice view, ca::usize offset, ca::usize length) noexcept
{
    return offset <= view.size() && length <= view.size() - offset;
}

/// @brief 取子视图；越界返回空视图而非异常（供防御式路径使用）。
inline ByteSlice subOrEmpty(ByteSlice view, ca::usize offset, ca::usize length) noexcept
{
    if (length == 0 || !covers(view, offset, length)) {
        return ByteSlice{};
    }
    return ByteSlice(view.data() + offset, length);
}

/// @brief 从任意 offset 开始的顺序读取器（小端）。
///
/// 每次 @ref at 都会在源 `Bytes` 上切一个共享存储的视图；读取代价与 libca
/// `Bytes` 的单次 get 相同，多出一次 shared_ptr 引用计数。取舍是读取面不再
/// 手写端序位移，源字节的所有权与视图语义统一由 libca 提供。
class Reader
{
public:
    /// @brief 空读取器（Result 存储需要默认构造；remaining() 恒为 0）。
    Reader() noexcept = default;

    /// @brief 在 source 的 offset 处创建读取器；offset 越界即 Err(Truncated)。
    static Result<Reader, ReadError> at(const ca::core::Bytes& source,
                                        ca::usize offset) noexcept
    {
        if (offset > source.len()) {
            return Err(ReadError::Truncated);
        }
        if (offset == source.len()) {
            return Ok(Reader{ca::core::Bytes{}, offset, 0});
        }
        // 先校验再 slice：libca 的 slice 越界会抛 std::out_of_range。
        return Ok(Reader{source.slice(offset, source.len()), offset, source.len() - offset});
    }

    /// @brief 绝对位置（相对源字节流起点）。
    ca::usize pos() const noexcept { return base_ + consumed(); }

    /// @brief 已消费字节数（相对创建时的 offset）。
    ca::usize consumed() const noexcept { return size_ - bytes_.remaining(); }

    ca::usize remaining() const noexcept { return bytes_.remaining(); }
    bool eof() const noexcept { return bytes_.remaining() == 0; }

    /// @brief 当前剩余字节的零拷贝视图（空时返回空视图）。
    ByteSlice remainingView() const noexcept
    {
        const ca::usize n = bytes_.remaining();
        return n == 0 ? ByteSlice{} : ByteSlice{bytes_.as_ptr(), n};
    }

    Result<ca::u8, ReadError> u8()
    {
        const Result<ca::u8, ca::core::BytesError> r = bytes_.get_u8();
        if (r.is_err()) {
            return Err(ReadError::Truncated);
        }
        return Ok(r.unwrap());
    }

    Result<ca::u16, ReadError> u16()
    {
        const Result<ca::u16, ca::core::BytesError> r = bytes_.get_u16_le();
        if (r.is_err()) {
            return Err(ReadError::Truncated);
        }
        return Ok(r.unwrap());
    }

    Result<ca::u32, ReadError> u32()
    {
        const Result<ca::u32, ca::core::BytesError> r = bytes_.get_u32_le();
        if (r.is_err()) {
            return Err(ReadError::Truncated);
        }
        return Ok(r.unwrap());
    }

    /// @brief 取 n 字节视图并前进；不足即 Err(Truncated)。
    Result<ByteSlice, ReadError> take(ca::usize n)
    {
        if (n > bytes_.remaining()) {
            return Err(ReadError::Truncated);
        }
        if (n == 0) {
            return Ok(ByteSlice{});
        }
        const ByteSlice v{bytes_.as_ptr(), n};
        (void)bytes_.advance(n);  // n <= remaining() 已校验，不会失败
        return Ok(v);
    }

    /// @brief 跳过 n 字节；不足即 Err(Truncated)。
    Result<void, ReadError> skip(ca::usize n)
    {
        if (bytes_.advance(n).is_err()) {
            return Err(ReadError::Truncated);
        }
        return Ok();
    }

private:
    Reader(ca::core::Bytes bytes, ca::usize base, ca::usize size) noexcept
        : bytes_(std::move(bytes)), base_(base), size_(size)
    {
    }

    ca::core::Bytes bytes_;
    ca::usize base_ = 0;
    ca::usize size_ = 0;
};

/// @brief 小端追加一个 u16 到输出缓冲。
inline void appendU16(std::vector<ca::u8>& out, ca::u16 value)
{
    out.push_back(static_cast<ca::u8>(value & 0xFFu));
    out.push_back(static_cast<ca::u8>(value >> 8));
}

/// @brief 小端追加一个 u32 到输出缓冲。
inline void appendU32(std::vector<ca::u8>& out, ca::u32 value)
{
    appendU16(out, static_cast<ca::u16>(value & 0xFFFFu));
    appendU16(out, static_cast<ca::u16>(value >> 16));
}

/// @brief 覆盖写 out[offset, offset+4) 为小端 u32。
inline void putU32(std::vector<ca::u8>& out, ca::usize offset, ca::u32 value)
{
    out[offset] = static_cast<ca::u8>(value & 0xFFu);
    out[offset + 1] = static_cast<ca::u8>((value >> 8) & 0xFFu);
    out[offset + 2] = static_cast<ca::u8>((value >> 16) & 0xFFu);
    out[offset + 3] = static_cast<ca::u8>(value >> 24);
}

/// @brief 无符号值能否落在 4/8/16/32 位域宽内。
inline bool fitsU4(ca::u64 value) noexcept { return value <= 0xFu; }
inline bool fitsU8(ca::u64 value) noexcept { return value <= 0xFFu; }
inline bool fitsU16(ca::u64 value) noexcept { return value <= 0xFFFFu; }
inline bool fitsU32(ca::u64 value) noexcept { return value <= 0xFFFFFFFFu; }

/// @brief 有符号值能否落在 4/8/16/32 位域宽内。
inline bool fitsI4(ca::i64 value) noexcept { return value >= -8 && value <= 7; }
inline bool fitsI8(ca::i64 value) noexcept { return value >= -128 && value <= 127; }
inline bool fitsI16(ca::i64 value) noexcept { return value >= -32768 && value <= 32767; }
inline bool fitsI32(ca::i64 value) noexcept
{
    return value >= -2147483647LL - 1 && value <= 2147483647LL;
}

}   // namespace dex::core
