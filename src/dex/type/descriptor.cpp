/// @file        descriptor.cpp
/// @brief       DEX 类型/方法描述符解析实现。
#include "dex/type/descriptor.hpp"

namespace dex::type {

namespace {

constexpr ca::u32 kMaxArrayDims = 255;

bool isReservedClassNameChar(char c) noexcept
{
    return c == '.' || c == '[' || c == ';';
}

Result<TypeDesc, DescError> parseTypeAt(std::string_view descriptor, ca::usize& pos) noexcept
{
    ca::u32 dims = 0;
    while (pos < descriptor.size() && descriptor[pos] == '[') {
        ++dims;
        ++pos;
        if (dims > kMaxArrayDims) {
            return Err(DescError::NestingTooDeep);
        }
    }
    if (pos >= descriptor.size()) {
        return Err(DescError::Truncated);
    }

    TypeDesc type;
    type.array_dims = dims;

    switch (descriptor[pos]) {
    case 'Z':
        type.primitive = BaseType::Boolean;
        ++pos;
        break;
    case 'B':
        type.primitive = BaseType::Byte;
        ++pos;
        break;
    case 'S':
        type.primitive = BaseType::Short;
        ++pos;
        break;
    case 'C':
        type.primitive = BaseType::Char;
        ++pos;
        break;
    case 'I':
        type.primitive = BaseType::Int;
        ++pos;
        break;
    case 'J':
        type.primitive = BaseType::Long;
        ++pos;
        break;
    case 'F':
        type.primitive = BaseType::Float;
        ++pos;
        break;
    case 'D':
        type.primitive = BaseType::Double;
        ++pos;
        break;
    case 'L': {
        ++pos;
        const ca::usize nameBegin = pos;
        const ca::usize terminator = descriptor.find(';', pos);
        if (terminator == std::string_view::npos) {
            return Err(DescError::Truncated);
        }
        const std::string_view name = descriptor.substr(nameBegin, terminator - nameBegin);
        if (name.empty()) {
            return Err(DescError::BadClassName);
        }
        for (const char c : name) {
            if (isReservedClassNameChar(c)) {
                return Err(DescError::BadClassName);
            }
        }
        type.kind = TypeDesc::Kind::Class;
        type.class_name = name;
        pos = terminator + 1;
        break;
    }
    default:
        // 包含 V：V 只在方法返回位，由 parseMethodDescriptor 单独处理。
        return Err(DescError::BadBaseType);
    }

    return Ok(type);
}

}   // namespace

Result<TypeDesc, DescError> parseFieldType(std::string_view descriptor) noexcept
{
    if (descriptor.empty()) {
        return Err(DescError::Empty);
    }

    ca::usize pos = 0;
    const Result<TypeDesc, DescError> type = parseTypeAt(descriptor, pos);
    if (type.is_err()) {
        return Err(type.unwrap_err());
    }
    if (pos != descriptor.size()) {
        return Err(DescError::TrailingChars);
    }
    return type;
}

Result<MethodDesc, DescError> parseMethodDescriptor(std::string_view descriptor)
{
    if (descriptor.empty()) {
        return Err(DescError::Empty);
    }
    if (descriptor.front() != '(') {
        return Err(DescError::BadMethodShape);
    }

    MethodDesc method;
    ca::usize pos = 1;
    while (pos < descriptor.size() && descriptor[pos] != ')') {
        const Result<TypeDesc, DescError> param = parseTypeAt(descriptor, pos);
        if (param.is_err()) {
            return Err(param.unwrap_err());
        }
        method.params.push_back(param.unwrap());
    }
    if (pos >= descriptor.size()) {
        return Err(DescError::Truncated);
    }

    ++pos;  // ')'
    if (pos >= descriptor.size()) {
        return Err(DescError::Truncated);
    }
    if (descriptor[pos] == 'V') {
        method.ret_void = true;
        ++pos;
    } else {
        const Result<TypeDesc, DescError> ret = parseTypeAt(descriptor, pos);
        if (ret.is_err()) {
            return Err(ret.unwrap_err());
        }
        method.ret = ret.unwrap();
    }

    if (pos != descriptor.size()) {
        return Err(DescError::TrailingChars);
    }
    return Ok(method);
}

bool isValidFieldType(std::string_view descriptor) noexcept
{
    return parseFieldType(descriptor).is_ok();
}

const char* to_string(DescError e) noexcept
{
    switch (e) {
    case DescError::Ok:
        return "Ok";
    case DescError::Empty:
        return "Empty";
    case DescError::Truncated:
        return "Truncated";
    case DescError::TrailingChars:
        return "TrailingChars";
    case DescError::BadBaseType:
        return "BadBaseType";
    case DescError::BadClassName:
        return "BadClassName";
    case DescError::BadMethodShape:
        return "BadMethodShape";
    case DescError::NestingTooDeep:
        return "NestingTooDeep";
    }
    return "Unknown";
}

}   // namespace dex::type
