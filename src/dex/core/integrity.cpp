/// @file        integrity.cpp
/// @brief       adler32 / SHA-1 校验字段实现。
#include "dex/core/integrity.hpp"

#include <algorithm>
#include <cstring>

#include "libca/crypto/sha1.hpp"

namespace dex::core {

namespace {

constexpr ca::u32 kAdlerMod = 65521u;
// 在 32 位累加器溢出前做取模的最大字节数（zlib 同款常数）。
constexpr ca::usize kAdlerChunk = 5552u;

constexpr ca::u32 kChecksumStart = 12u;
constexpr ca::u32 kSignatureStart = 32u;

}   // namespace

ca::u32 adler32(ByteSlice data) noexcept
{
    ca::u32 a = 1;
    ca::u32 b = 0;

    ca::usize i = 0;
    while (i < data.size()) {
        const ca::usize chunk = std::min(data.size() - i, kAdlerChunk);
        for (ca::usize n = 0; n < chunk; ++n) {
            a += data[i + n];
            b += a;
        }
        a %= kAdlerMod;
        b %= kAdlerMod;
        i += chunk;
    }

    return (b << 16) | a;
}

std::array<ca::u8, 20> sha1Digest(ByteSlice data)
{
    ca::crypto::SHA1 sha;
    if (!data.empty()) {
        sha.add(data.data(), data.size());
    }
    std::array<ca::u8, 20> out{};
    sha.get_hash(out.data());
    return out;
}

Integrity verifyIntegrity(ByteSlice source,
                          ca::u32 expectedChecksum,
                          const std::array<ca::u8, 20>& expectedSignature)
{
    Integrity result;

    if (source.size() >= kChecksumStart) {
        const ByteSlice covered =
            subOrEmpty(source, kChecksumStart, source.size() - kChecksumStart);
        result.checksumOk = adler32(covered) == expectedChecksum;
    }

    if (source.size() >= kSignatureStart) {
        const ByteSlice covered =
            subOrEmpty(source, kSignatureStart, source.size() - kSignatureStart);
        result.signatureOk = sha1Digest(covered) == expectedSignature;
    }

    return result;
}

}   // namespace dex::core
