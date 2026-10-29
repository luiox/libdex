/// @file        opcode.cpp
/// @brief       操作码元数据表与格式宽度。
#include "dex/opcode.hpp"
namespace dex::core {


ca::u32 insnWidth(InsnFormat format) noexcept
{
    switch (format) {
    case InsnFormat::F10x:
    case InsnFormat::F12x:
    case InsnFormat::F11n:
    case InsnFormat::F11x:
    case InsnFormat::F10t:
        return 1;
    case InsnFormat::F20t:
    case InsnFormat::F22x:
    case InsnFormat::F21t:
    case InsnFormat::F21s:
    case InsnFormat::F21h:
    case InsnFormat::F21c:
    case InsnFormat::F23x:
    case InsnFormat::F22b:
    case InsnFormat::F22t:
    case InsnFormat::F22s:
    case InsnFormat::F22c:
        return 2;
    case InsnFormat::F30t:
    case InsnFormat::F32x:
    case InsnFormat::F31i:
    case InsnFormat::F31t:
    case InsnFormat::F31c:
    case InsnFormat::F35c:
    case InsnFormat::F3rc:
        return 3;
    case InsnFormat::F45cc:
    case InsnFormat::F4rcc:
        return 4;
    case InsnFormat::F51l:
        return 5;
    case InsnFormat::Unknown:
    case InsnFormat::Payload:
        return 0;
    }
    return 0;
}

const char* to_string(InsnFormat format) noexcept
{
    switch (format) {
    case InsnFormat::Unknown:
        return "unknown";
    case InsnFormat::F10x:
        return "10x";
    case InsnFormat::F12x:
        return "12x";
    case InsnFormat::F11n:
        return "11n";
    case InsnFormat::F11x:
        return "11x";
    case InsnFormat::F10t:
        return "10t";
    case InsnFormat::F20t:
        return "20t";
    case InsnFormat::F22x:
        return "22x";
    case InsnFormat::F21t:
        return "21t";
    case InsnFormat::F21s:
        return "21s";
    case InsnFormat::F21h:
        return "21h";
    case InsnFormat::F21c:
        return "21c";
    case InsnFormat::F23x:
        return "23x";
    case InsnFormat::F22b:
        return "22b";
    case InsnFormat::F22t:
        return "22t";
    case InsnFormat::F22s:
        return "22s";
    case InsnFormat::F22c:
        return "22c";
    case InsnFormat::F30t:
        return "30t";
    case InsnFormat::F32x:
        return "32x";
    case InsnFormat::F31i:
        return "31i";
    case InsnFormat::F31t:
        return "31t";
    case InsnFormat::F31c:
        return "31c";
    case InsnFormat::F35c:
        return "35c";
    case InsnFormat::F3rc:
        return "3rc";
    case InsnFormat::F45cc:
        return "45cc";
    case InsnFormat::F4rcc:
        return "4rcc";
    case InsnFormat::F51l:
        return "51l";
    case InsnFormat::Payload:
        return "payload";
    }
    return "unknown";
}

}   // namespace dex::core
