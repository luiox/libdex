/// @file        method_editor.cpp
/// @brief       方法体构建门面实现。
#include "dex/core/method_editor.hpp"

namespace dex::core {

Result<MethodBody, CodeDomError> MethodEditor::commit()
{
    Result<LoweredCode, CodeDomError> lowered = unit_.lower(true);
    if (lowered.is_err()) {
        return Err(lowered.unwrap_err());
    }
    LoweredCode code = std::move(lowered).unwrap();
    MethodBody body;
    body.item = std::move(code.item);
    body.insns = std::move(code.insns);
    return Ok(std::move(body));
}

}   // namespace dex::core
