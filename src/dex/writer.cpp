/// @file        writer.cpp
/// @brief       DEX 未修改透传写回。
#include "dex/writer.hpp"

namespace dex::core {

Result<std::vector<ca::u8>, WriteError> writeDex(const DexFile& dex)
{
    if (!dex.hasSource()) {
        return Err(WriteError::MissingSource);
    }

    const ByteSlice src = dex.source();
    return Ok(std::vector<ca::u8>(src.data(), src.data() + src.size()));
}

}   // namespace dex::core
