/// @file        assemble.cpp
/// @brief       libsmali 汇编器实现。
#include "smali/assemble.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include "jstr/conversion.hpp"

#include "dex/annotation.hpp"
#include "dex/code_item.hpp"
#include "dex/code_dom.hpp"
#include "dex/encoded_value.hpp"
#include "dex/error.hpp"
#include "dex/insn_edit.hpp"
#include "dex/method_editor.hpp"
#include "dex/debug_info.hpp"
#include "smali/opcodes.hpp"

namespace dex::smali {

using core::AnnotationItem;
using core::Err;
using core::ReadError;
using core::WriteError;
using core::Ok;
using core::BuildOptions;
using core::CodeItem;
using core::DexFile;
using core::EncodedAnnotation;
using core::EncodedValue;
using core::Insn;
using core::MethodEditor;

const char* to_string(AsmErrorCode e) noexcept
{
    switch (e) {
    case AsmErrorCode::Ok: return "ok";
    case AsmErrorCode::Syntax: return "syntax error";
    case AsmErrorCode::UnknownDirective: return "unknown directive";
    case AsmErrorCode::UnknownMnemonic: return "unknown mnemonic";
    case AsmErrorCode::BadRegister: return "bad register";
    case AsmErrorCode::BadLabel: return "bad label";
    case AsmErrorCode::BadRef: return "bad reference";
    case AsmErrorCode::BadValue: return "bad value";
    case AsmErrorCode::Overflow: return "operand overflow";
    case AsmErrorCode::Duplicate: return "duplicate definition";
    case AsmErrorCode::ModelError: return "model error";
    }
    return "unknown";
}

/// CodeDomError → AsmErrorCode 的唯一桥。switch 穷举且无 default：新增
/// CodeDomError 枚举值而不同步这里，libsmali 目标在编译期直接报错。
AsmErrorCode mapCodeDom(core::CodeDomError e) noexcept
{
    switch (e) {
        case core::CodeDomError::Ok: return AsmErrorCode::ModelError;
        case core::CodeDomError::StaleHandle: return AsmErrorCode::ModelError;
        case core::CodeDomError::UnknownLabel: return AsmErrorCode::BadLabel;
        case core::CodeDomError::StillUsed: return AsmErrorCode::ModelError;
        case core::CodeDomError::DanglingLabel: return AsmErrorCode::BadLabel;
        case core::CodeDomError::Unencodable: return AsmErrorCode::Overflow;
        case core::CodeDomError::MisalignedPayload: return AsmErrorCode::Overflow;
        case core::CodeDomError::BadTryRegion: return AsmErrorCode::BadLabel;
        case core::CodeDomError::BadShape: return AsmErrorCode::ModelError;
    }
    return AsmErrorCode::ModelError;
}

/// InsnEncodeError → AsmErrorCode 的唯一桥，穷举约束同 mapCodeDom。
AsmErrorCode mapInsnEncode(core::InsnEncodeError e) noexcept
{
    switch (e) {
        case core::InsnEncodeError::Ok: return AsmErrorCode::ModelError;
        case core::InsnEncodeError::BadFormat: return AsmErrorCode::ModelError;
        case core::InsnEncodeError::OperandOverflow: return AsmErrorCode::Overflow;
        case core::InsnEncodeError::BadPayload: return AsmErrorCode::ModelError;
        case core::InsnEncodeError::MisalignedPayload: return AsmErrorCode::Overflow;
    }
    return AsmErrorCode::ModelError;
}

namespace {

template <typename T>
using R = core::Result<T, AsmError>;

AsmError fail(AsmErrorCode c, ca::u32 line, std::string detail)
{
    return AsmError::make(c, line, std::move(detail));
}

// ---- 行级词法 ----

/// @brief 把一行拆成 token；引号字符串是一个 token，花括号独立成 token。
std::vector<std::string> tokenize(std::string_view line)
{
    std::vector<std::string> out;
    std::string cur;
    bool inQuote = false;
    auto flush = [&] {
        if (!cur.empty()) {
            out.push_back(std::move(cur));
            cur.clear();
        }
    };
    for (char ch : line) {
        if (inQuote) {
            cur.push_back(ch);
            if (ch == '"') {
                inQuote = false;
            }
            continue;
        }
        switch (ch) {
        case '"':
            inQuote = true;
            cur.push_back(ch);
            break;
        case ' ':
        case '\t':
        case ',':
            // 裸逗号一律当分隔符：baksmali 规范文本与自家空格文本都能吃
            // （引号内的逗号走 inQuote 分支，不受影响）。
            flush();
            break;
        case '{':
        case '}':
            flush();
            out.emplace_back(1, ch);
            break;
        default:
            cur.push_back(ch);
        }
    }
    flush();
    return out;
}

bool startsWith(std::string_view s, char c)
{
    return !s.empty() && s.front() == c;
}

bool isReg(std::string_view t)
{
    return t.size() >= 2 && (t[0] == 'v' || t[0] == 'p') &&
           t.substr(1).find_first_not_of("0123456789") == std::string_view::npos;
}

R<ca::u16> parseReg(const std::string& t, ca::u32 firstParamReg, ca::u16 registersSize,
                    ca::u32 line, bool hasParams = true)
{
    if (!isReg(t)) {
        return Err(fail(AsmErrorCode::BadRegister, line, t));
    }
    const ca::u32 n = static_cast<ca::u32>(std::strtoul(t.c_str() + 1, nullptr, 10));
    ca::u32 raw = n;
    if (t[0] == 'p') {
        if (!hasParams) {
            return Err(fail(AsmErrorCode::BadRegister, line,
                            "p-register in a method without parameters"));
        }
        raw = firstParamReg + n;
    }
    if (raw >= registersSize) {
        return Err(fail(AsmErrorCode::BadRegister, line,
                        t + " >= .registers " + std::to_string(registersSize)));
    }
    return Ok(static_cast<ca::u16>(raw));
}

R<ca::i64> parseInt(std::string_view t, ca::u32 line)
{
    if (t.empty()) {
        return Err(fail(AsmErrorCode::BadValue, line, "empty integer"));
    }
    std::string s(t);
    // 0x 前缀按无符号解析后按补码回卷：反汇编端对宽字面量按位模式渲染
    // （如 const/high16 的 0xffff0000），超出 i64 的形式 strtoll 会静默
    // 钳位成 LLONG_MAX。其余进制 ERANGE 显式报错。
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0 ||
        s.rfind("-0x", 0) == 0 || s.rfind("-0X", 0) == 0) {
        const bool neg = s[0] == '-';
        errno = 0;
        const ca::u64 u = std::strtoull(neg ? s.c_str() + 1 : s.c_str(), nullptr, 0);
        if (errno == ERANGE) {
            return Err(fail(AsmErrorCode::Overflow, line, s));
        }
        const ca::i64 v = static_cast<ca::i64>(neg ? 0u - u : u);
        return Ok(v);
    }
    errno = 0;
    const ca::i64 v = std::strtoll(s.c_str(), nullptr, 0);
    if (errno == ERANGE) {
        return Err(fail(AsmErrorCode::Overflow, line, s));
    }
    return Ok(v);
}

/// @brief 解析 smali 引用：字段 Lx;->n:T、方法 Lx;->n(params)ret、类型、
///        字符串字面量。返回 token 形态给调用方按 opcode 解释。
struct Ref
{
    enum Kind { None, Str, Type, Field, Method, Proto, Named } kind = None;
    std::string cls;
    std::string name;
    std::string type;    ///< 字段类型 / 方法返回类型
    std::vector<std::string> params;
    ca::u32 number = 0;  ///< @N 形态（call_site / method_handle）
};

R<Ref> parseRef(const std::string& tok, ca::u32 line)
{
    Ref r;
    if (startsWith(tok, '"') && tok.back() == '"') {
        r.kind = Ref::Str;
        r.name = tok.substr(1, tok.size() - 2);
        return Ok(std::move(r));
    }
    if (startsWith(tok, '@')) {
        r.kind = Ref::Named;
        r.number = static_cast<ca::u32>(std::strtoul(tok.c_str() + 1, nullptr, 10));
        return Ok(std::move(r));
    }
    const std::size_t arrow = tok.find("->");
    if (arrow == std::string::npos) {
        // 类型描述符。
        if (tok.find(';') == std::string::npos &&
            tok.find_first_of("[BCDFIJSZV") != 0) {
            return Err(fail(AsmErrorCode::BadRef, line, tok));
        }
        r.kind = Ref::Type;
        r.cls = tok;
        return Ok(std::move(r));
    }
    r.cls = tok.substr(0, arrow);
    const std::string rest = tok.substr(arrow + 2);
    const std::size_t paren = rest.find('(');
    if (paren == std::string::npos) {
        // 字段。
        const std::size_t colon = rest.rfind(':');
        if (colon == std::string::npos) {
            return Err(fail(AsmErrorCode::BadRef, line, tok));
        }
        r.kind = Ref::Field;
        r.name = rest.substr(0, colon);
        r.type = rest.substr(colon + 1);
        return Ok(std::move(r));
    }
    r.kind = Ref::Method;
    r.name = rest.substr(0, paren);
    const std::size_t close = rest.find(')', paren);
    if (close == std::string::npos) {
        return Err(fail(AsmErrorCode::BadRef, line, tok));
    }
    const std::string params = rest.substr(paren + 1, close - paren - 1);
    r.type = rest.substr(close + 1);
    // 参数描述符逐个切分（J/D 双宽不影响文本切分）；畸形截断显式报错，
    // 不能让 ';' 扫描越过字符串末尾。
    for (std::size_t i = 0; i < params.size();) {
        std::size_t j = i;
        while (j < params.size() && params[j] == '[') {
            ++j;
        }
        if (j >= params.size()) {
            return Err(fail(AsmErrorCode::BadRef, line, tok));
        }
        j += 1;  // 基类型或 L
        if (params[j - 1] == 'L') {
            while (j < params.size() && params[j] != ';') {
                ++j;
            }
            if (j >= params.size()) {
                return Err(fail(AsmErrorCode::BadRef, line, tok));
            }
            j += 1;
        }
        r.params.push_back(params.substr(i, j - i));
        i = j;
    }
    return Ok(std::move(r));
}

/// @brief 解一个 UTF-8 码点；成功返回消耗的字节数，非法或截断返回 0。
std::size_t decodeUtf8(const std::string& s, std::size_t at, char32_t* out) noexcept
{
    const auto byteAt = [&s](std::size_t k) {
        return static_cast<ca::u32>(static_cast<unsigned char>(s[k]));
    };
    const ca::u32 lead = byteAt(at);
    if (lead < 0x80u) {
        *out = static_cast<char32_t>(lead);
        return 1;
    }
    std::size_t need = 0;
    ca::u32 cp = 0;
    if (lead >= 0xC2u && lead <= 0xDFu) {  // C0/C1 是 overlong
        need = 2;
        cp = lead & 0x1Fu;
    } else if (lead >= 0xE0u && lead <= 0xEFu) {
        need = 3;
        cp = lead & 0x0Fu;
    } else if (lead >= 0xF0u && lead <= 0xF4u) {
        need = 4;
        cp = lead & 0x07u;
    } else {
        return 0;
    }
    if (at + need > s.size()) {
        return 0;
    }
    for (std::size_t k = 1; k < need; ++k) {
        const ca::u32 cc = byteAt(at + k);
        if ((cc & 0xC0u) != 0x80u) {
            return 0;
        }
        cp = (cp << 6) | (cc & 0x3Fu);
    }
    if ((need == 2 && cp < 0x80u) || (need == 3 && cp < 0x800u) ||
        (need == 4 && cp < 0x10000u) || cp > 0x10FFFFu ||
        (cp >= 0xD800u && cp <= 0xDFFFu)) {
        return 0;
    }
    *out = static_cast<char32_t>(cp);
    return need;
}

int hexValue(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

R<ca::u32> internString(DexFile& dex, const std::string& escaped, ca::u32 line)
{
    // 文本层的转义还原成 UTF-16，再编码为 MUTF-8 intern。
    std::u16string u16;
    for (std::size_t i = 0; i < escaped.size();) {
        if (escaped[i] != '\\') {
            char32_t cp = 0;
            const std::size_t used = decodeUtf8(escaped, i, &cp);
            if (used == 0) {
                return Err(fail(AsmErrorCode::BadValue, line, "invalid UTF-8"));
            }
            if (cp >= 0x10000) {
                const char32_t v = cp - 0x10000;
                u16.push_back(static_cast<char16_t>(0xD800u + (v >> 10)));
                u16.push_back(static_cast<char16_t>(0xDC00u + (v & 0x3FFu)));
            } else {
                u16.push_back(static_cast<char16_t>(cp));
            }
            i += used;
            continue;
        }
        ++i;
        if (i >= escaped.size()) {
            return Err(fail(AsmErrorCode::BadValue, line, "dangling backslash"));
        }
        const char c = escaped[i];
        switch (c) {
        case 'n': u16.push_back(u'\n'); ++i; break;
        case 'r': u16.push_back(u'\r'); ++i; break;
        case 't': u16.push_back(u'\t'); ++i; break;
        case '"': u16.push_back(u'"'); ++i; break;
        case '\\': u16.push_back(u'\\'); ++i; break;
        case 'u': {
            if (i + 4 >= escaped.size()) {
                return Err(fail(AsmErrorCode::BadValue, line, "short \\u escape"));
            }
            ca::u32 cp = 0;
            for (std::size_t k = 1; k <= 4; ++k) {
                const int v = hexValue(escaped[i + k]);
                if (v < 0) {
                    return Err(fail(AsmErrorCode::BadValue, line, "bad \\u escape"));
                }
                cp = (cp << 4) | static_cast<ca::u32>(v);
            }
            u16.push_back(static_cast<char16_t>(cp));
            i += 5;
            break;
        }
        default:
            return Err(fail(AsmErrorCode::BadValue, line, std::string("\\") + c));
        }
    }
    const Result<jstr::MUtf8String, jstr::EncodingError> mutf8 =
        jstr::utf16_to_mutf8(u16);
    if (mutf8.is_err()) {
        return Err(fail(AsmErrorCode::BadValue, line, "mutf8 encode"));
    }
    const jstr::MUtf8String& ms = mutf8.unwrap();
    const Result<ca::u32, core::ReadError> idx =
        dex.internString(ms.view());
    if (idx.is_err()) {
        return Err(fail(AsmErrorCode::ModelError, line, "internString"));
    }
    return Ok(idx.unwrap());
}

R<ca::u32> internType(DexFile& dex, const std::string& desc, ca::u32 line)
{
    const Result<ca::u32, core::ReadError> idx = dex.addType(desc);
    if (idx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, desc));
    }
    return Ok(idx.unwrap());
}

R<ca::u32> resolveField(DexFile& dex, const Ref& r, ca::u32 classIdx, ca::u32 line)
{
    const Result<ca::u32, core::ReadError> typeIdx = dex.addType(r.type);
    if (typeIdx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.type));
    }
    const Result<ca::u32, core::ReadError> cls = dex.addType(r.cls);
    if (cls.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.cls));
    }
    const R<ca::u32> name = internString(dex, r.name, line);
    if (name.is_err()) {
        return Err(name.unwrap_err());
    }
    const Result<ca::u32, core::ReadError> idx =
        dex.addField(static_cast<ca::u16>(cls.unwrap()),
                     static_cast<ca::u16>(typeIdx.unwrap()), name.unwrap());
    if (idx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.cls + "->" + r.name));
    }
    (void)classIdx;
    return Ok(idx.unwrap());
}

R<ca::u32> resolveProto(DexFile& dex, const Ref& r, ca::u32 line)
{
    const Result<ca::u32, core::ReadError> ret = dex.addType(r.type);
    if (ret.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.type));
    }
    std::vector<ca::u32> params;
    for (const std::string& p : r.params) {
        const Result<ca::u32, core::ReadError> t = dex.addType(p);
        if (t.is_err()) {
            return Err(fail(AsmErrorCode::BadRef, line, p));
        }
        params.push_back(t.unwrap());
    }
    const Result<ca::u32, core::ReadError> idx =
        dex.addProtoWithParams(ret.unwrap(), params);
    if (idx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, "proto"));
    }
    return Ok(idx.unwrap());
}

R<ca::u32> resolveMethod(DexFile& dex, const Ref& r, ca::u32 line)
{
    const R<ca::u32> proto = resolveProto(dex, r, line);
    if (proto.is_err()) {
        return Err(proto.unwrap_err());
    }
    const Result<ca::u32, core::ReadError> cls = dex.addType(r.cls);
    if (cls.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.cls));
    }
    const R<ca::u32> name = internString(dex, r.name, line);
    if (name.is_err()) {
        return Err(name.unwrap_err());
    }
    const Result<ca::u32, core::ReadError> idx =
        dex.addMethod(static_cast<ca::u16>(cls.unwrap()), proto.unwrap(), name.unwrap());
    if (idx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, line, r.cls + "->" + r.name));
    }
    return Ok(idx.unwrap());
}

// ---- 值解析（encoded_value）----

struct ValueParser
{
    DexFile& dex;
    const std::string& text;  // 整段值文本（可含空格/花括号）
    std::size_t pos = 0;
    ca::u32 line = 0;

    void skipWs()
    {
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == ',')) {
            ++pos;
        }
    }

    R<EncodedValue> parse(ca::u32 depth = 0)
    {
        if (depth > 32) {
            return Err(fail(AsmErrorCode::BadValue, line, "nesting too deep"));
        }
        skipWs();
        if (pos >= text.size()) {
            return Err(fail(AsmErrorCode::BadValue, line, "unexpected end"));
        }

        // 数组。
        if (text[pos] == '{') {
            ++pos;
            EncodedValue v;
            v.type = core::EncodedValueType::Array;
            for (;;) {
                skipWs();
                if (pos < text.size() && text[pos] == '}') {
                    ++pos;
                    break;
                }
                if (pos >= text.size()) {
                    return Err(fail(AsmErrorCode::BadValue, line, "unterminated array"));
                }
                R<EncodedValue> e = parse(depth + 1);
                if (e.is_err()) {
                    return e;
                }
                v.array.push_back(std::move(e).unwrap());
            }
            return Ok(std::move(v));
        }

        // 子注解。
        if (text.compare(pos, 14, ".subannotation") == 0) {
            pos += 14;
            skipWs();
            const std::size_t start = pos;
            while (pos < text.size() && text[pos] != ' ') {
                ++pos;
            }
            const Result<ca::u32, core::ReadError> typeIdx =
                dex.addType(text.substr(start, pos - start));
            if (typeIdx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, line, text.substr(start, pos - start)));
            }
            EncodedValue v;
            v.type = core::EncodedValueType::Annotation;
            v.annotation.reset(new EncodedAnnotation());
            v.annotation->typeIdx = typeIdx.unwrap();
            for (;;) {
                skipWs();
                if (text.compare(pos, 18, ".end subannotation") == 0) {
                    pos += 18;
                    break;
                }
                // name = value
                const std::size_t eq = text.find('=', pos);
                if (eq == std::string::npos) {
                    return Err(fail(AsmErrorCode::BadValue, line, "annotation element"));
                }
                std::string name;
                for (std::size_t i = pos; i < eq; ++i) {
                    if (text[i] != ' ') {
                        name.push_back(text[i]);
                    }
                }
                pos = eq + 1;
                R<EncodedValue> e = parse(depth + 1);
                if (e.is_err()) {
                    return e;
                }
                const R<ca::u32> nameIdx = internString(dex, name, line);
                if (nameIdx.is_err()) {
                    return Err(nameIdx.unwrap_err());
                }
                core::AnnotationElement elem;
                elem.nameIdx = nameIdx.unwrap();
                elem.value = std::move(e).unwrap();
                v.annotation->elements.push_back(std::move(elem));
            }
            return Ok(std::move(v));
        }

        // 取一个 token（到空格或右花括号，但引号字符串完整）。
        std::string tok;
        if (text[pos] == '"') {
            const std::size_t end = text.find('"', pos + 1);
            if (end == std::string::npos) {
                return Err(fail(AsmErrorCode::BadValue, line, "unterminated string"));
            }
            tok = text.substr(pos, end - pos + 1);
            pos = end + 1;
        } else {
            while (pos < text.size() && text[pos] != ' ' && text[pos] != ',' &&
                   text[pos] != '}') {
                tok.push_back(text[pos]);
                ++pos;
            }
        }
        if (tok.empty()) {
            return Err(fail(AsmErrorCode::BadValue, line, "empty token"));
        }
        // .enum / method-type 带空格后继 token，抓回来合并。
        if (tok == ".enum" || tok == "method-type") {
            skipWs();
            if (pos < text.size() && text[pos] == '"') {
                const std::size_t end = text.find('"', pos + 1);
                if (end == std::string::npos) {
                    return Err(fail(AsmErrorCode::BadValue, line, "unterminated string"));
                }
                tok += " " + text.substr(pos, end - pos + 1);
                pos = end + 1;
            } else {
                std::string rest;
                while (pos < text.size() && text[pos] != ' ' && text[pos] != ',' &&
                       text[pos] != '}') {
                    rest.push_back(text[pos]);
                    ++pos;
                }
                tok += " " + rest;
            }
        }
        return parseToken(tok, depth);
    }

    R<EncodedValue> parseToken(const std::string& tok, ca::u32 depth)
    {
        EncodedValue v;
        if (tok == "null") {
            v.type = core::EncodedValueType::Null;
            return Ok(std::move(v));
        }
        if (tok == "true" || tok == "false") {
            v.type = core::EncodedValueType::Boolean;
            v.boolean = tok == "true";
            return Ok(std::move(v));
        }
        if (tok.size() >= 3 && tok.front() == '\'' && tok.back() == '\'') {
            v.type = core::EncodedValueType::Char;
            const std::string body = tok.substr(1, tok.size() - 2);
            if (body.compare(0, 2, "\\u") == 0) {
                v.bits = std::strtoul(body.c_str() + 2, nullptr, 16);
            } else {
                v.bits = static_cast<unsigned char>(body[0]);
            }
            return Ok(std::move(v));
        }
        if (tok.front() == '"') {
            v.type = core::EncodedValueType::String;
            R<ca::u32> idx = internString(dex, tok.substr(1, tok.size() - 2), line);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            v.index = idx.unwrap();
            return Ok(std::move(v));
        }
        if (tok.compare(0, 6, ".enum ") == 0) {
            v.type = core::EncodedValueType::Enum;
            R<Ref> r = parseRef(tok.substr(6), line);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
            R<ca::u32> idx = resolveField(dex, r.unwrap(), 0, line);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            v.index = idx.unwrap();
            return Ok(std::move(v));
        }
        if (tok.compare(0, 12, "method-type ") == 0) {
            v.type = core::EncodedValueType::MethodType;
            R<Ref> r = parseRef(tok.substr(12), line);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
            R<ca::u32> idx = resolveProto(dex, r.unwrap(), line);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            v.index = idx.unwrap();
            return Ok(std::move(v));
        }
        if (tok.compare(0, 14, "method-handle@") == 0) {
            v.type = core::EncodedValueType::MethodHandle;
            v.index = static_cast<ca::u32>(std::strtoul(tok.c_str() + 14, nullptr, 10));
            return Ok(std::move(v));
        }
        // 浮点位模式 0x..F / 0x..D。
        if (tok.size() > 3 && tok[0] == '0' && tok[1] == 'x') {
            const char last = tok.back();
            if (last == 'F' || last == 'D') {
                const ca::u64 bits =
                    std::strtoull(tok.substr(2, tok.size() - 3).c_str(), nullptr, 16);
                v.type = last == 'F' ? core::EncodedValueType::Float
                                     : core::EncodedValueType::Double;
                v.bits = bits;
                return Ok(std::move(v));
            }
        }
        // 整数（含 b/s/L 后缀）。
        char last = tok.back();
        if (last == 'b' || last == 's' || last == 'L') {
            const std::string body = tok.substr(0, tok.size() - 1);
            const ca::i64 value = std::strtoll(body.c_str(), nullptr, 0);
            v.integer = value;
            v.type = last == 'b'   ? core::EncodedValueType::Byte
                     : last == 's' ? core::EncodedValueType::Short
                                   : core::EncodedValueType::Long;
            return Ok(std::move(v));
        }
        // 字段/方法/类型引用（注解值形态）。
        if (tok.find("->") != std::string::npos) {
            R<Ref> r = parseRef(tok, line);
            if (r.is_err()) {
                return Err(r.unwrap_err());
            }
            const Ref& rr = r.unwrap();
            if (rr.kind == Ref::Field) {
                v.type = core::EncodedValueType::Field;
                R<ca::u32> idx = resolveField(dex, rr, 0, line);
                if (idx.is_err()) {
                    return Err(idx.unwrap_err());
                }
                v.index = idx.unwrap();
                return Ok(std::move(v));
            }
            if (rr.kind == Ref::Method) {
                v.type = core::EncodedValueType::Method;
                R<ca::u32> idx = resolveMethod(dex, rr, line);
                if (idx.is_err()) {
                    return Err(idx.unwrap_err());
                }
                v.index = idx.unwrap();
                return Ok(std::move(v));
            }
            return Err(fail(AsmErrorCode::BadValue, line, tok));
        }
        if (tok[0] == 'L' || tok[0] == '[' ||
            (tok.size() == 1 && std::string("BCDFIJSZV").find(tok[0]) != std::string::npos)) {
            v.type = core::EncodedValueType::Type;
            R<ca::u32> idx = internType(dex, tok, line);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            v.index = idx.unwrap();
            return Ok(std::move(v));
        }
        // 普通整数 → Int。
        v.type = core::EncodedValueType::Int;
        v.integer = std::strtoll(tok.c_str(), nullptr, 0);
        return Ok(std::move(v));
    }
};

/// @brief 注解块的值文本：截掉 ".end annotation" 尾巴（块收集后可能残留）。
std::string stripEndAnnotation(std::string valueText)
{
    const std::size_t endAnn = valueText.find(".end annotation");
    if (endAnn != std::string::npos) {
        valueText = valueText.substr(0, endAnn);
    }
    return valueText;
}

R<EncodedValue> parseValue(DexFile& dex, const std::string& text, ca::u32 line)
{
    ValueParser p{dex, text, 0, line};
    return p.parse();
}

// ---- 方法体上下文 ----

struct DebugEvent
{
    enum Kind { Line, LocalStart, LocalStartExt, LocalEnd, LocalRestart, Prologue, Epilogue } kind;
    core::InsnId after{nullptr, core::kEndSlot, 0};  // 锚点：此槽之后（end = 流末）
    ca::i32 line = 0;
    ca::u32 reg = 0;
    ca::u32 nameIdx = 0;
    ca::u32 typeIdx = 0;
    ca::u32 sigIdx = 0;
};

}   // namespace

}   // namespace dex::smali

namespace dex::smali {

namespace {

using core::CodeUnit;
using core::InsnId;
using core::LabelId;
using core::MethodBody;
using core::TypedCatch;
using core::TryBlock;

std::string trimTok(const std::string& s)
{
    std::size_t a = 0;
    std::size_t b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '{' || s[a] == ',')) {
        ++a;
    }
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '}' ||
                     s[b - 1] == ',')) {
        --b;
    }
    return s.substr(a, b - a);
}

R<ca::u32> parseFlags(const std::vector<std::string>& toks, ca::u32 begin, ca::u32 line)
{
    ca::u32 flags = 0;
    for (ca::u32 i = begin; i < toks.size(); ++i) {
        const std::optional<ca::u32> f = accessFlagOf(toks[i]);
        if (!f) {
            return Err(fail(AsmErrorCode::Syntax, line, "unknown flag " + toks[i]));
        }
        flags |= *f;
    }
    return Ok(flags);
}

R<Ref> parseMethodSig(const std::string& tok, ca::u32 line)
{
    const std::size_t paren = tok.find('(');
    if (paren == std::string::npos) {
        return Err(fail(AsmErrorCode::Syntax, line, tok));
    }
    Ref r;
    r.kind = Ref::Method;
    r.name = tok.substr(0, paren);
    const std::size_t close = tok.find(')', paren);
    if (close == std::string::npos) {
        return Err(fail(AsmErrorCode::Syntax, line, tok));
    }
    const std::string params = tok.substr(paren + 1, close - paren - 1);
    r.type = tok.substr(close + 1);
    for (std::size_t i = 0; i < params.size();) {
        std::size_t j = i;
        while (j < params.size() && params[j] == '[') {
            ++j;
        }
        j += 1;
        if (j - 1 < params.size() && params[j - 1] == 'L') {
            while (j < params.size() && params[j] != ';') {
                ++j;
            }
            j += 1;
        }
        r.params.push_back(params.substr(i, j - i));
        i = j;
    }
    return Ok(std::move(r));
}

/// @brief 裸 proto 描述符 `(params)ret`（invoke-polymorphic 第二操作数）。
///        parseRef 只认 类型/字段/方法引用 形态，认不了这个，单独切。
R<Ref> parseProtoDesc(const std::string& tok, ca::u32 line)
{
    if (tok.empty() || tok[0] != '(') {
        return Err(fail(AsmErrorCode::BadRef, line, tok));
    }
    const std::size_t close = tok.find(')');
    if (close == std::string::npos) {
        return Err(fail(AsmErrorCode::BadRef, line, tok));
    }
    Ref r;
    r.kind = Ref::Proto;
    const std::string params = tok.substr(1, close - 1);
    r.type = tok.substr(close + 1);
    if (r.type.empty()) {
        return Err(fail(AsmErrorCode::BadRef, line, tok));
    }
    for (std::size_t i = 0; i < params.size();) {
        std::size_t j = i;
        while (j < params.size() && params[j] == '[') {
            ++j;
        }
        j += 1;
        if (j - 1 < params.size() && params[j - 1] == 'L') {
            while (j < params.size() && params[j] != ';') {
                ++j;
            }
            j += 1;
        }
        r.params.push_back(params.substr(i, j - i));
        i = j;
    }
    return Ok(std::move(r));
}

struct MethodCtx
{
    std::string name;
    ca::u32 accessFlags = 0;
    ca::u32 methodIdx = 0;
    bool isStatic = false;
    ca::u32 insSize = 0;
    std::unique_ptr<MethodEditor> editor;
    std::unordered_map<std::string, LabelId> labels;
    std::vector<std::string> pendingLabels;
    InsnId lastAppended{nullptr, core::kEndSlot, 0};
    std::vector<DebugEvent> events;
    std::vector<std::string> paramNames;
    std::vector<DebugEvent::Kind> markers;  // prologue/epilogue 暂存
    struct CatchLine
    {
        std::string typeDesc;
        std::string start;
        std::string end;
        std::string handler;
    };
    std::vector<CatchLine> catches;
    std::vector<AnnotationItem> methodAnnotations;
    std::map<ca::u32, std::vector<AnnotationItem>> parameterAnnotations;
    // payload 绑定：31t 行的期望 label 名与 switch 句柄。
    InsnId pendingSwitch{nullptr, core::kEndSlot, 0};
    std::string pendingSwitchLabel;
    ca::u32 line = 0;

    LabelId label(CodeUnit& unit, const std::string& name)
    {
        auto it = labels.find(name);
        if (it != labels.end()) {
            return it->second;
        }
        const LabelId id = unit.newLabel();
        labels.emplace(name, id);
        return id;
    }

    void bindPending(CodeUnit& unit, InsnId slot)
    {
        for (const std::string& n : pendingLabels) {
            (void)unit.bindLabel(label(unit, n), slot);
        }
        pendingLabels.clear();
    }
};

R<void> assembleMethod(DexFile& dex, SmaliAssembler& self, const std::string& header,
                       const std::vector<std::string>& bodyLines,
                       const std::vector<ca::u32>& lineNos, ca::u32 classDefIdx,
                       ca::u32 classIdx)
{
    const ca::u32 headLine = lineNos.empty() ? 0 : lineNos.front();
    const std::vector<std::string> toks = tokenize(header);
    std::size_t sigPos = 1;
    ca::u32 flagBits = 0;
    while (sigPos < toks.size() && accessFlagOf(toks[sigPos]).has_value()) {
        flagBits |= *accessFlagOf(toks[sigPos]);
        ++sigPos;
    }
    if (sigPos >= toks.size()) {
        return Err(fail(AsmErrorCode::Syntax, headLine, header));
    }
    R<Ref> sig = parseMethodSig(toks[sigPos], headLine);
    if (sig.is_err()) {
        return Err(sig.unwrap_err());
    }

    MethodCtx ctx;
    ctx.accessFlags = flagBits;
    ctx.isStatic = (ctx.accessFlags & 0x8) != 0;
    ctx.line = headLine;

    // 方法索引与参数槽位。
    const Result<ca::u32, core::ReadError> retIdx = dex.addType(sig.unwrap().type);
    if (retIdx.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, headLine, sig.unwrap().type));
    }
    std::vector<ca::u32> paramIdxs;
    ca::u32 slots = ctx.isStatic ? 0 : 1;
    for (const std::string& p : sig.unwrap().params) {
        const Result<ca::u32, core::ReadError> t = dex.addType(p);
        if (t.is_err()) {
            return Err(fail(AsmErrorCode::BadRef, headLine, p));
        }
        paramIdxs.push_back(t.unwrap());
        slots += (p == "J" || p == "D") ? 2 : 1;
    }
    ctx.insSize = slots;
    const Result<ca::u32, core::ReadError> proto =
        dex.addProtoWithParams(retIdx.unwrap(), paramIdxs);
    if (proto.is_err()) {
        return Err(fail(AsmErrorCode::BadRef, headLine, "proto"));
    }
    R<ca::u32> nameIdx = internString(dex, sig.unwrap().name, headLine);
    if (nameIdx.is_err()) {
        return Err(nameIdx.unwrap_err());
    }
    const Result<ca::u32, core::ReadError> m =
        dex.addMethod(static_cast<ca::u16>(classIdx), proto.unwrap(), nameIdx.unwrap());
    if (m.is_err()) {
        return Err(fail(AsmErrorCode::ModelError, headLine, "addMethod"));
    }
    ctx.methodIdx = m.unwrap();

    // .registers 预扫。
    ca::u16 registersSize = static_cast<ca::u16>(ctx.insSize);
    for (const std::string& b : bodyLines) {
        const std::vector<std::string> t = tokenize(b);
        if (t.size() == 2 && t[0] == ".registers") {
            registersSize = static_cast<ca::u16>(
                std::strtoul(t[1].c_str(), nullptr, 10));
        }
    }
    // abstract/native 无代码体：d8 发 registersSize=0，不按 insSize 抬。
    const bool noCodeBody =
        (ctx.accessFlags & (0x0400u /*ACC_ABSTRACT*/ | 0x0100u /*ACC_NATIVE*/)) != 0;
    if (!noCodeBody && registersSize < ctx.insSize) {
        registersSize = static_cast<ca::u16>(ctx.insSize);
    }
    ctx.editor.reset(new MethodEditor(registersSize,
                                      static_cast<ca::u16>(ctx.insSize), 0));
    CodeUnit& unit = ctx.editor->unit();
    const ca::u32 firstParamReg =
        static_cast<ca::u32>(registersSize) >= ctx.insSize
            ? static_cast<ca::u32>(registersSize) - ctx.insSize
            : 0u;

    const auto appendInsn = [&](Insn insn) -> InsnId {
        const InsnId id = unit.append(std::move(insn));
        ctx.bindPending(unit, id);
        ctx.lastAppended = id;
        return id;
    };

    for (std::size_t bi = 0; bi < bodyLines.size(); ++bi) {
        const std::string raw = bodyLines[bi];
        const ca::u32 ln = lineNos.empty() ? 0 : lineNos[bi];
        const std::vector<std::string> toks = tokenize(raw);
        if (toks.empty()) {
            continue;
        }
        const std::string& t0 = toks[0];

        // ---- label 定义 ----
        if (startsWith(t0, ':')) {
            if (std::find(ctx.pendingLabels.begin(), ctx.pendingLabels.end(), t0) ==
                ctx.pendingLabels.end()) {
                ctx.pendingLabels.push_back(t0);
            }
            continue;
        }

        // ---- debug / 结构指令块 ----
        if (t0 == ".registers") {
            continue;
        }
        if (t0 == ".params") {
            for (std::size_t i = 1; i < toks.size(); ++i) {
                if (toks[i].size() >= 2 && toks[i].front() == '"' &&
                    toks[i].back() == '"') {
                    ctx.paramNames.push_back(toks[i].substr(1, toks[i].size() - 2));
                }
            }
            continue;
        }
        if (t0 == ".prologue" || t0 == ".epilogue") {
            DebugEvent e;
            e.kind = t0 == ".prologue" ? DebugEvent::Prologue : DebugEvent::Epilogue;
            e.after = ctx.lastAppended;
            ctx.events.push_back(e);
            continue;
        }
        if (t0 == ".line") {
            if (toks.size() != 2) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            DebugEvent e;
            e.kind = DebugEvent::Line;
            e.line = static_cast<ca::i32>(std::strtol(toks[1].c_str(), nullptr, 10));
            e.after = ctx.lastAppended;
            ctx.events.push_back(e);
            continue;
        }
        // ".end local"/".restart local" 含空格，按空白切分后 t0 只是
        // ".end"/".restart"；拼接第二个 token 还原完整指令名。
        std::string localDir = t0;
        if ((t0 == ".end" || t0 == ".restart") && toks.size() >= 2 && toks[1] == "local") {
            localDir = t0 + " local";
        }
        if (localDir == ".local" || localDir == ".end local" || localDir == ".restart local") {
            DebugEvent e;
            e.kind = localDir == ".local"        ? DebugEvent::LocalStart
                     : localDir == ".end local" ? DebugEvent::LocalEnd
                                                : DebugEvent::LocalRestart;
            if (localDir == ".local") {
                if (toks.size() < 3) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                R<ca::u16> reg = parseReg(toks[1], firstParamReg, registersSize, ln);
                if (reg.is_err()) {
                    return Err(reg.unwrap_err());
                }
                e.reg = reg.unwrap();
                const std::size_t nameStart = raw.find('"');
                const std::size_t nameEnd = raw.find('"', nameStart + 1);
                if (nameStart == std::string::npos || nameEnd == std::string::npos) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                const std::string name = raw.substr(nameStart + 1, nameEnd - nameStart - 1);
                std::string rest = raw.substr(nameEnd + 1);
                const std::size_t colon = rest.find(':');
                if (colon == std::string::npos) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                rest = rest.substr(colon + 1);
                std::string typeDesc;
                std::string sigStr;
                const std::size_t comma = rest.find(',');
                if (comma != std::string::npos) {
                    sigStr = rest.substr(comma + 1);
                    rest = rest.substr(0, comma);
                }
                for (char c : rest) {
                    if (c != ' ' && c != '"') {
                        typeDesc.push_back(c);
                    }
                }
                const Result<ca::u32, core::ReadError> tIdx = dex.addType(typeDesc);
                if (tIdx.is_err()) {
                    return Err(fail(AsmErrorCode::BadRef, ln, typeDesc));
                }
                e.typeIdx = tIdx.unwrap();
                if (name.empty()) {
                    e.nameIdx = DexFile::kNoIndex;
                } else {
                    R<ca::u32> n = internString(dex, name, ln);
                    if (n.is_err()) {
                        return Err(n.unwrap_err());
                    }
                    e.nameIdx = n.unwrap();
                }
                if (!sigStr.empty()) {
                    std::string sig;
                    for (char c : sigStr) {
                        if (c != ' ' && c != '"') {
                            sig.push_back(c);
                        }
                    }
                    e.kind = DebugEvent::LocalStartExt;
                    R<ca::u32> sg = internString(dex, sig, ln);
                    if (sg.is_err()) {
                        return Err(sg.unwrap_err());
                    }
                    e.sigIdx = sg.unwrap();
                }
            } else {
                if (toks.size() != 3) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                R<ca::u16> reg = parseReg(toks[2], firstParamReg, registersSize, ln);
                if (reg.is_err()) {
                    return Err(reg.unwrap_err());
                }
                e.reg = reg.unwrap();
            }
            e.after = ctx.lastAppended;
            ctx.events.push_back(e);
            continue;
        }
        if (t0 == ".catch" || t0 == ".catchall") {
            MethodCtx::CatchLine c;
            if (t0 == ".catch") {
                if (toks.size() < 2) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                c.typeDesc = toks[1];
            }
            const std::size_t open = raw.find('{');
            const std::size_t dots = raw.find("..", open);
            const std::size_t close = raw.find('}', open);
            if (open == std::string::npos || dots == std::string::npos ||
                close == std::string::npos) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            c.start = trimTok(raw.substr(open + 1, dots - open - 1));
            c.end = trimTok(raw.substr(dots + 2, close - dots - 2));
            c.handler = trimTok(raw.substr(close + 1));
            if (c.start.empty() || c.end.empty() || c.handler.empty() ||
                !startsWith(c.start, ':') || !startsWith(c.end, ':') ||
                !startsWith(c.handler, ':')) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            if (t0 == ".catch") {
                const Result<ca::u32, core::ReadError> tIdx = dex.addType(c.typeDesc);
                if (tIdx.is_err()) {
                    return Err(fail(AsmErrorCode::BadRef, ln, c.typeDesc));
                }
            }
            ctx.catches.push_back(std::move(c));
            continue;
        }
        if (t0 == ".annotation") {
            std::string acc = raw;
            if (acc.find(".end annotation") == std::string::npos) {
                while (bi + 1 < bodyLines.size() &&
                       bodyLines[bi + 1].find(".end annotation") == std::string::npos) {
                    acc += " " + bodyLines[++bi];
                }
                ++bi;  // 单行时终结符在行内，不多吃
            }
            const std::size_t sp1 = acc.find(' ');
            const std::size_t sp2 = acc.find(' ', sp1 + 1);
            const std::string vis = acc.substr(sp1 + 1, sp2 - sp1 - 1);
            const std::size_t typeStart = sp2 + 1;
            const std::size_t typeEnd = acc.find(' ', typeStart);
            const std::string typeDesc =
                acc.substr(typeStart, typeEnd == std::string::npos
                                          ? std::string::npos
                                          : typeEnd - typeStart);
            std::string valueText =
                typeEnd == std::string::npos ? "" : acc.substr(typeEnd);
                valueText = stripEndAnnotation(std::move(valueText));
            const std::size_t endAnn = valueText.find(".end annotation");
            if (endAnn != std::string::npos) {
                valueText = valueText.substr(0, endAnn);
            }
            R<EncodedValue> v = parseValue(
                dex, ".subannotation " + typeDesc + valueText + " .end subannotation",
                ln);
            if (v.is_err()) {
                return Err(v.unwrap_err());
            }
            EncodedValue val = std::move(v).unwrap();
            if (val.annotation == nullptr) {
                return Err(fail(AsmErrorCode::BadValue, ln, "annotation"));
            }
            AnnotationItem item;
            item.visibility =
                vis == "runtime" ? 1 : (vis == "system" ? 2 : 0);
            item.annotation = std::move(*val.annotation);
            ctx.methodAnnotations.push_back(std::move(item));
            continue;
        }
        if (t0 == ".parameter-annotation") {
            if (toks.size() != 2) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            const ca::u32 param =
                static_cast<ca::u32>(std::strtoul(toks[1].c_str(), nullptr, 10));
            std::vector<AnnotationItem> items;
            // 注解块收集到下一个非 .annotation 行为止——反汇编输出不生成
            // .end parameter-annotation 终结符；若出现则按终结符消费。
            while (bi + 1 < bodyLines.size() &&
                   bodyLines[bi + 1].compare(0, 11, ".annotation") == 0) {
                ++bi;
                std::string acc = bodyLines[bi];
                if (acc.find(".end annotation") == std::string::npos) {
                    while (bi + 1 < bodyLines.size() &&
                           bodyLines[bi + 1].find(".end annotation") ==
                               std::string::npos) {
                        acc += " " + bodyLines[++bi];
                    }
                    ++bi;  // 单行时终结符在行内，不多吃
                }
                const std::size_t sp1 = acc.find(' ');
                const std::size_t sp2 = acc.find(' ', sp1 + 1);
                const std::string vis = acc.substr(sp1 + 1, sp2 - sp1 - 1);
                const std::size_t typeStart = sp2 + 1;
                const std::size_t typeEnd = acc.find(' ', typeStart);
                const std::string typeDesc =
                    acc.substr(typeStart, typeEnd == std::string::npos
                                              ? std::string::npos
                                              : typeEnd - typeStart);
                std::string valueText =
                    typeEnd == std::string::npos ? "" : acc.substr(typeEnd);
                    valueText = stripEndAnnotation(std::move(valueText));
                R<EncodedValue> v = parseValue(
                    dex, ".subannotation " + typeDesc + valueText + " .end subannotation",
                    ln);
                if (v.is_err()) {
                    return Err(v.unwrap_err());
                }
                EncodedValue val = std::move(v).unwrap();
                if (val.annotation == nullptr) {
                    return Err(fail(AsmErrorCode::BadValue, ln, "annotation"));
                }
                AnnotationItem item;
                item.visibility =
                    vis == "runtime" ? 1 : (vis == "system" ? 2 : 0);
                item.annotation = std::move(*val.annotation);
                items.push_back(std::move(item));
            }
            if (bi + 1 < bodyLines.size() &&
                bodyLines[bi + 1].find(".end parameter-annotation") !=
                    std::string::npos) {
                ++bi;  // 显式终结符（本仓库反汇编不生成，容忍手写）
            }
            ctx.parameterAnnotations.emplace(param, std::move(items));
            continue;
        }

        // ---- payload 块（就地成为槽位）----
        if (t0 == ".packed-switch" || t0 == ".sparse-switch" ||
            t0 == ".fill-array-data") {
            if (ctx.pendingSwitch.slot == core::kEndSlot) {
                return Err(fail(AsmErrorCode::UnknownDirective, ln,
                                "payload without a preceding switch insn"));
            }
            // 绑定 payload 的 label（pending 里的名字应为 31t 引用的名字）。
            std::string payloadLabel = ctx.pendingLabels.empty()
                                           ? ctx.pendingSwitchLabel
                                           : ctx.pendingLabels.front();
            InsnId payloadSlot{nullptr, core::kEndSlot, 0};
            std::vector<LabelId> targets;
            if (t0 == ".packed-switch") {
                if (toks.size() != 2) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                R<ca::i64> key = parseInt(toks[1], ln);
                if (key.is_err()) {
                    return Err(key.unwrap_err());
                }
                std::vector<std::string> targetNames;
                std::vector<ca::i32> zeros;
                while (bi + 1 < bodyLines.size() &&
                       bodyLines[bi + 1].find(".end packed-switch") ==
                           std::string::npos) {
                    ++bi;
                    targetNames.push_back(trimTok(bodyLines[bi]));
                    zeros.push_back(0);
                }
                ++bi;
                Result<core::PayloadInsn, core::InsnEncodeError> p =
                    core::makePackedSwitchPayload(
                        static_cast<ca::i32>(key.unwrap()), zeros);
                if (p.is_err()) {
                    return Err(fail(mapInsnEncode(p.unwrap_err()), ln, "packed payload"));
                }
                core::PayloadInsn built = std::move(p).unwrap();
                for (const std::string& n : targetNames) {
                    targets.push_back(ctx.label(unit, n));
                }
                payloadSlot = unit.append(built.insn, std::move(built.storage));
            } else if (t0 == ".sparse-switch") {
                std::vector<ca::i32> keys;
                std::vector<ca::i32> zeros;
                std::vector<std::string> targetNames;
                while (bi + 1 < bodyLines.size() &&
                       bodyLines[bi + 1].find(".end sparse-switch") ==
                           std::string::npos) {
                    ++bi;
                    const std::string line = bodyLines[bi];
                    const std::size_t arrow = line.find("->");
                    if (arrow == std::string::npos) {
                        return Err(fail(AsmErrorCode::Syntax, ln, line));
                    }
                    R<ca::i64> k = parseInt(trimTok(line.substr(0, arrow)), ln);
                    if (k.is_err()) {
                        return Err(k.unwrap_err());
                    }
                    keys.push_back(static_cast<ca::i32>(k.unwrap()));
                    zeros.push_back(0);
                    targetNames.push_back(trimTok(line.substr(arrow + 2)));
                }
                ++bi;
                Result<core::PayloadInsn, core::InsnEncodeError> p =
                    core::makeSparseSwitchPayload(keys, zeros);
                if (p.is_err()) {
                    return Err(fail(mapInsnEncode(p.unwrap_err()), ln, "sparse payload"));
                }
                core::PayloadInsn built = std::move(p).unwrap();
                for (const std::string& n : targetNames) {
                    targets.push_back(ctx.label(unit, n));
                }
                payloadSlot = unit.append(built.insn, std::move(built.storage));
            } else {
                // .fill-array-data + .array-data w ... .end array-data
                while (bi + 1 < bodyLines.size() &&
                       trimTok(bodyLines[bi + 1]) != ".end fill-array-data" &&
                       tokenize(bodyLines[bi + 1])[0] != ".array-data") {
                    ++bi;
                }
                if (bi + 1 >= bodyLines.size() ||
                    tokenize(bodyLines[bi + 1])[0] != ".array-data") {
                    return Err(fail(AsmErrorCode::Syntax, ln,
                                    "missing .array-data after .fill-array-data"));
                }
                ++bi;
                const std::vector<std::string> ad = tokenize(bodyLines[bi]);
                if (ad.size() != 2) {
                    return Err(fail(AsmErrorCode::Syntax, ln, bodyLines[bi]));
                }
                const ca::u32 width =
                    static_cast<ca::u32>(std::strtoul(ad[1].c_str(), nullptr, 10));
                std::vector<ca::u8> data;
                while (bi + 1 < bodyLines.size() &&
                       bodyLines[bi + 1].find(".end array-data") == std::string::npos) {
                    ++bi;
                    for (const std::string& t : tokenize(bodyLines[bi])) {
                        const ca::u32 b =
                            static_cast<ca::u32>(std::strtoul(t.c_str(), nullptr, 16));
                        data.push_back(static_cast<ca::u8>(b));
                    }
                }
                ++bi;  // .end array-data
                ++bi;  // .end fill-array-data
                Result<core::PayloadInsn, core::InsnEncodeError> p =
                    core::makeFillArrayDataPayload(static_cast<ca::u16>(width),
                                                   std::move(data));
                if (p.is_err()) {
                    return Err(fail(mapInsnEncode(p.unwrap_err()), ln, "fill payload"));
                }
                core::PayloadInsn built = std::move(p).unwrap();
                payloadSlot = unit.append(built.insn, std::move(built.storage));
            }
            ctx.bindPending(unit, payloadSlot);
            if (Result<void, core::CodeDomError> b =
                    unit.bindPayload(ctx.pendingSwitch, payloadSlot, targets);
                b.is_err()) {
                return Err(fail(mapCodeDom(b.unwrap_err()), ln, payloadLabel));
            }
            ctx.pendingSwitch = InsnId{nullptr, core::kEndSlot, 0};
            ctx.lastAppended = payloadSlot;
            continue;
        }

        if (startsWith(t0, '.')) {
            return Err(fail(AsmErrorCode::UnknownDirective, ln, t0));
        }

        // ---- 指令 ----
        const std::optional<Mnemonic> mne = opcodeOf(t0);
        if (!mne) {
            return Err(fail(AsmErrorCode::UnknownMnemonic, ln, t0));
        }
        Insn insn;
        insn.opcode = mne->opcode;
        insn.format = mne->format;
        insn.width = core::insnWidth(mne->format);
        bool handled = true;

        switch (mne->format) {
        case core::InsnFormat::F10x:
            break;
        case core::InsnFormat::F12x: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            if (a.is_err() || b.is_err()) {
                return Err(a.is_err() ? a.unwrap_err() : b.unwrap_err());
            }
            insn.registerCount = 2;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            break;
        }
        case core::InsnFormat::F11x: {
            if (toks.size() != 2) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            if (a.is_err()) { return Err(a.unwrap_err()); }
            insn.registerCount = 1;
            insn.registers[0] = a.unwrap();
            break;
        }
        case core::InsnFormat::F11n:
        case core::InsnFormat::F21s:
        case core::InsnFormat::F21h:
        case core::InsnFormat::F31i:
        case core::InsnFormat::F51l: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::i64> v = parseInt(toks[2], ln);
            if (a.is_err() || v.is_err()) {
                return Err(a.is_err() ? a.unwrap_err() : v.unwrap_err());
            }
            insn.registerCount = 1;
            insn.registers[0] = a.unwrap();
            insn.literal = v.unwrap();
            break;
        }
        case core::InsnFormat::F21c:
        case core::InsnFormat::F31c: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            if (a.is_err()) { return Err(a.unwrap_err()); }
            R<Ref> r = parseRef(toks[2], ln);
            if (r.is_err()) { return Err(r.unwrap_err()); }
            const Ref& rr = r.unwrap();
            ca::u32 idx = 0;
            if (mne->opcode == 0x1a || mne->opcode == 0x1b) {
                if (rr.kind != Ref::Str) {
                    return Err(fail(AsmErrorCode::BadRef, ln, toks[2]));
                }
                R<ca::u32> i2 = internString(dex, rr.name, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::String;
            } else if (mne->opcode == 0x1c || mne->opcode == 0x22 ||
                       mne->opcode == 0x1f) {
                if (rr.kind != Ref::Type) {
                    return Err(fail(AsmErrorCode::BadRef, ln, toks[2]));
                }
                R<ca::u32> i2 = internType(dex, rr.cls, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::Type;
            } else if (mne->opcode == 0xfe) {
                insn.indexKind = core::IndexKind::MethodHandle;
                idx = rr.number;
            } else if (mne->opcode == 0xff) {
                R<ca::u32> i2 = resolveProto(dex, rr, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::Proto;
            } else {
                if (rr.kind != Ref::Field) {
                    return Err(fail(AsmErrorCode::BadRef, ln, toks[2]));
                }
                R<ca::u32> i2 = resolveField(dex, rr, classIdx, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::Field;
            }
            insn.registerCount = 1;
            insn.registers[0] = a.unwrap();
            insn.index = idx;
            break;
        }
        case core::InsnFormat::F23x: {
            if (toks.size() != 4) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            R<ca::u16> c2 = parseReg(toks[3], firstParamReg, registersSize, ln);
            if (a.is_err() || b.is_err() || c2.is_err()) {
                return Err(a.is_err()   ? a.unwrap_err()
                           : b.is_err() ? b.unwrap_err()
                                        : c2.unwrap_err());
            }
            insn.registerCount = 3;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            insn.registers[2] = c2.unwrap();
            break;
        }
        case core::InsnFormat::F22b:
        case core::InsnFormat::F22s: {
            if (toks.size() != 4) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            R<ca::i64> v = parseInt(toks[3], ln);
            if (a.is_err() || b.is_err() || v.is_err()) {
                return Err(a.is_err()   ? a.unwrap_err()
                           : b.is_err() ? b.unwrap_err()
                                        : v.unwrap_err());
            }
            insn.registerCount = 2;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            insn.literal = v.unwrap();
            break;
        }
        case core::InsnFormat::F22c: {
            if (toks.size() != 4) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            if (a.is_err() || b.is_err()) {
                return Err(a.is_err() ? a.unwrap_err() : b.unwrap_err());
            }
            R<Ref> r = parseRef(toks[3], ln);
            if (r.is_err()) { return Err(r.unwrap_err()); }
            const Ref& rr = r.unwrap();
            insn.registerCount = 2;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            // 0x1f/0x20/0x23 是 type 操作数，iget/iput 族是 field 操作数。
            const bool typeOp = mne->opcode == 0x1f || mne->opcode == 0x20 ||
                                mne->opcode == 0x23;
            if (typeOp) {
                if (rr.kind != Ref::Type) {
                    return Err(fail(AsmErrorCode::BadRef, ln, toks[3]));
                }
                R<ca::u32> i2 = internType(dex, rr.cls, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                insn.index = i2.unwrap();
                insn.indexKind = core::IndexKind::Type;
            } else {
                if (rr.kind != Ref::Field) {
                    return Err(fail(AsmErrorCode::BadRef, ln, toks[3]));
                }
                R<ca::u32> i2 = resolveField(dex, rr, classIdx, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                insn.index = i2.unwrap();
                insn.indexKind = core::IndexKind::Field;
            }
            break;
        }
        case core::InsnFormat::F22x:
        case core::InsnFormat::F32x: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            if (a.is_err() || b.is_err()) {
                return Err(a.is_err() ? a.unwrap_err() : b.unwrap_err());
            }
            // F22x/F32x 的第二寄存器在 List 布局的 registers[1]；startRegister
            // 是 Range 布局（3rc/4rcc）专用，编码器不读它。
            insn.registerCount = 2;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            break;
        }
        case core::InsnFormat::F10t:
        case core::InsnFormat::F20t:
        case core::InsnFormat::F30t: {
            if (toks.size() != 2) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            const LabelId id = ctx.label(unit, toks[1]);
            const InsnId slot = appendInsn(insn);
            if (Result<void, core::CodeDomError> b = unit.bindBranch(slot, id); b.is_err()) {
                return Err(fail(mapCodeDom(b.unwrap_err()), ln, toks[1]));
            }
            handled = false;
            break;
        }
        case core::InsnFormat::F21t: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            if (a.is_err()) { return Err(a.unwrap_err()); }
            insn.registerCount = 1;
            insn.registers[0] = a.unwrap();
            const LabelId id = ctx.label(unit, toks[2]);
            const InsnId slot = appendInsn(insn);
            if (Result<void, core::CodeDomError> b = unit.bindBranch(slot, id); b.is_err()) {
                return Err(fail(mapCodeDom(b.unwrap_err()), ln, toks[2]));
            }
            handled = false;
            break;
        }
        case core::InsnFormat::F22t: {
            if (toks.size() != 4) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            R<ca::u16> b = parseReg(toks[2], firstParamReg, registersSize, ln);
            if (a.is_err() || b.is_err()) {
                return Err(a.is_err() ? a.unwrap_err() : b.unwrap_err());
            }
            insn.registerCount = 2;
            insn.registers[0] = a.unwrap();
            insn.registers[1] = b.unwrap();
            const LabelId id = ctx.label(unit, toks[3]);
            const InsnId slot = appendInsn(insn);
            if (Result<void, core::CodeDomError> bd = unit.bindBranch(slot, id); bd.is_err()) {
                return Err(fail(mapCodeDom(bd.unwrap_err()), ln, toks[3]));
            }
            handled = false;
            break;
        }
        case core::InsnFormat::F31t: {
            if (toks.size() != 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            R<ca::u16> a = parseReg(toks[1], firstParamReg, registersSize, ln);
            if (a.is_err()) { return Err(a.unwrap_err()); }
            insn.registerCount = 1;
            insn.registers[0] = a.unwrap();
            const InsnId slot = appendInsn(insn);
            ctx.pendingSwitch = slot;
            ctx.pendingSwitchLabel = toks[2];
            // 校验 label 存在于 payload 块（未定义也能先建，绑定时核对）。
            (void)ctx.label(unit, toks[2]);
            handled = false;
            break;
        }
        case core::InsnFormat::F35c:
        case core::InsnFormat::F3rc:
        case core::InsnFormat::F45cc:
        case core::InsnFormat::F4rcc: {
            if (toks.size() < 3) { return Err(fail(AsmErrorCode::Syntax, ln, raw)); }
            // 寄存器组可能被 tokenizer 拆成 { / p0 / , / p1 / } 多个 token，
            // 重新拼接到 '}' 收口；列表元素间补逗号，range 的 .. 直连。
            std::string regs = toks[1];
            std::size_t regEnd = 1;
            std::string prevTok = toks[1];
            while (regEnd + 1 < toks.size() && regs.find('}') == std::string::npos) {
                const std::string nx = toks[++regEnd];
                const bool attach = regs.back() == '{' || nx == "}" || nx == ".." ||
                                    prevTok == "..";
                if (!attach) {
                    regs += ',';
                }
                regs += nx;
                prevTok = nx;
            }
            if (regEnd + 2 > toks.size()) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            // 引用与 proto 从 regEnd+1 起重排。
            std::vector<std::string> rest(toks.begin() + static_cast<long>(regEnd) + 1,
                                          toks.end());
            if (rest.size() < 1) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            if (regs.front() != '{' || regs.find('}') == std::string::npos) {
                return Err(fail(AsmErrorCode::Syntax, ln, raw));
            }
            const std::string regList = regs.substr(1, regs.find('}') - 1);
            std::vector<ca::u16> rs;
            if (!regList.empty()) {
                const std::size_t range = regList.find("..");
                if (range != std::string::npos) {
                    R<ca::u16> a = parseReg(trimTok(regList.substr(0, range)),
                                            firstParamReg, registersSize, ln);
                    R<ca::u16> b = parseReg(trimTok(regList.substr(range + 2)),
                                            firstParamReg, registersSize, ln);
                    if (a.is_err() || b.is_err()) {
                        return Err(a.is_err() ? a.unwrap_err() : b.unwrap_err());
                    }
                    for (ca::u32 r0 = a.unwrap(); r0 <= b.unwrap(); ++r0) {
                        rs.push_back(static_cast<ca::u16>(r0));
                    }
                } else {
                    std::string cur;
                    for (std::size_t i = 0; i <= regList.size(); ++i) {
                        if (i == regList.size() || regList[i] == ',') {
                            const std::string one = trimTok(cur);
                            if (!one.empty()) {
                                R<ca::u16> a = parseReg(one, firstParamReg,
                                                        registersSize, ln);
                                if (a.is_err()) { return Err(a.unwrap_err()); }
                                rs.push_back(a.unwrap());
                            }
                            cur.clear();
                        } else if (regList[i] != ' ') {
                            cur.push_back(regList[i]);
                        }
                    }
                }
            }
            R<Ref> r = parseRef(rest[0], ln);
            if (r.is_err()) { return Err(r.unwrap_err()); }
            const Ref& rr = r.unwrap();
            ca::u32 idx = 0;
            if (mne->opcode == 0x24 || mne->opcode == 0x25) {
                if (rr.kind != Ref::Type) {
                    return Err(fail(AsmErrorCode::BadRef, ln, rest[0]));
                }
                R<ca::u32> i2 = internType(dex, rr.cls, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::Type;
            } else if (mne->opcode == 0xfc || mne->opcode == 0xfd) {
                insn.indexKind = core::IndexKind::CallSite;
                idx = rr.number;
            } else {
                if (rr.kind != Ref::Method) {
                    return Err(fail(AsmErrorCode::BadRef, ln, rest[0]));
                }
                R<ca::u32> i2 = resolveMethod(dex, rr, ln);
                if (i2.is_err()) { return Err(i2.unwrap_err()); }
                idx = i2.unwrap();
                insn.indexKind = core::IndexKind::Method;
            }
            insn.index = idx;
            if (mne->format == core::InsnFormat::F3rc ||
                mne->format == core::InsnFormat::F4rcc) {
                // 3rc 的寄存器计数是 u8；过宽当场报错而非静默截断。
                if (rs.size() > 255) {
                    return Err(fail(AsmErrorCode::Overflow, ln, raw));
                }
                insn.startRegister = rs.empty() ? 0 : rs.front();
                insn.registerCount = static_cast<ca::u8>(rs.size());
            } else {
                if (rs.size() > 5) {
                    return Err(fail(AsmErrorCode::Overflow, ln, raw));
                }
                insn.registerCount = static_cast<ca::u8>(rs.size());
                for (ca::u32 k = 0; k < rs.size(); ++k) {
                    insn.registers[k] = rs[k];
                }
            }
            if (mne->format == core::InsnFormat::F45cc ||
                mne->format == core::InsnFormat::F4rcc) {
                if (rest.size() != 2) {
                    return Err(fail(AsmErrorCode::Syntax, ln, raw));
                }
                R<Ref> pr = parseProtoDesc(rest[1], ln);
                if (pr.is_err()) { return Err(pr.unwrap_err()); }
                R<ca::u32> pi = resolveProto(dex, pr.unwrap(), ln);
                if (pi.is_err()) { return Err(pi.unwrap_err()); }
                insn.protoIndex = pi.unwrap();
                insn.hasProtoIndex = true;
            }
            break;
        }
        default:
            handled = true;
            break;
        }
        if (handled) {
            (void)appendInsn(insn);
        }
    }

    // 流末 pending label。
    ctx.bindPending(unit, unit.end());

    // try/catch（label 化，地址由 lower 解析）。
    for (const MethodCtx::CatchLine& c : ctx.catches) {
        core::HandlerDom dom;
        if (!c.typeDesc.empty()) {
            const Result<ca::u32, core::ReadError> tIdx = dex.addType(c.typeDesc);
            if (tIdx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, ctx.line, c.typeDesc));
            }
            dom.typed.push_back(core::HandlerDom::Typed{tIdx.unwrap(),
                                                        ctx.label(unit, c.handler)});
        } else {
            dom.hasCatchAll = true;
            dom.catchAll = ctx.label(unit, c.handler);
        }
        const ca::u32 hidx = unit.addHandler(dom);
        if (Result<void, core::CodeDomError> r =
                unit.addTry(ctx.label(unit, c.start), ctx.label(unit, c.end), hidx);
            r.is_err()) {
            return Err(fail(mapCodeDom(r.unwrap_err()), ctx.line, c.start));
        }
    }

    // commit：lower（payload 对齐）+ 产物。
    const Result<core::MethodBody, core::CodeDomError> body = ctx.editor->commit();
    if (body.is_err()) {
        return Err(fail(mapCodeDom(body.unwrap_err()), ctx.line,
                        core::to_string(body.unwrap_err())));
    }
    MethodBody out = std::move(body).unwrap();

    // debug 事件 → ops（commit 后地址已定）。
    if (!ctx.events.empty() || !ctx.paramNames.empty()) {
        struct Resolved
        {
            ca::u32 addr;
            int order;
            DebugEvent::Kind kind;
            ca::i32 line = 0;
            ca::u32 reg = 0;
            ca::u32 nameIdx = 0;
            ca::u32 typeIdx = 0;
            ca::u32 sigIdx = 0;
        };
        std::vector<Resolved> resolved;
        // 流末地址 = 最后一条槽的地址+宽度；空体为 0。
        ca::u32 totalEnd = 0;
        {
            InsnId it = unit.first();
            while (unit.valid(it)) {
                const Result<ca::u32, core::CodeDomError> a = unit.addressOf(it);
                totalEnd = a.is_err() ? 0 : a.unwrap() + unit.get(it).width;
                it = unit.next(it);
            }
        }
        const auto addrAfter = [&](const InsnId& after) -> R<ca::u32> {
            if (after.slot == core::kEndSlot) {
                // kEndSlot 锚 = 尚无前驱指令（方法开头）→ 地址 0，而非流末。
                return Ok(static_cast<ca::u32>(0));
            }
            const Result<ca::u32, core::CodeDomError> a = unit.addressOf(after);
            if (a.is_err()) {
                return Err(fail(mapCodeDom(a.unwrap_err()), ctx.line, "anchor"));
            }
            return Ok(a.unwrap() + unit.get(after).width);
        };
        for (const DebugEvent& e : ctx.events) {
            R<ca::u32> a = addrAfter(e.after);
            if (a.is_err()) {
                return Err(a.unwrap_err());
            }
            resolved.push_back(Resolved{a.unwrap(), 0, e.kind, e.line, e.reg,
                                        e.nameIdx, e.typeIdx, e.sigIdx});
        }
        std::stable_sort(resolved.begin(), resolved.end(),
                         [](const Resolved& x, const Resolved& y) {
                             if (x.addr != y.addr) {
                                 return x.addr < y.addr;
                             }
                             return x.order < y.order;
                         });

        core::DebugInfo info;
        for (const std::string& n : ctx.paramNames) {
            if (n.empty()) {
                info.parameterNames.push_back(DexFile::kNoIndex);
                continue;
            }
            R<ca::u32> idx = internString(dex, n, ctx.line);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            info.parameterNames.push_back(idx.unwrap());
        }
        ca::u32 lastAddr = 0;
        ca::i32 lastLine = 0;
        bool haveLine = false;
        for (const Resolved& e : resolved) {
            if (haveLine && e.addr == lastAddr &&
                e.kind == DebugEvent::Line && e.line == lastLine) {
                continue;
            }
            if (e.kind == DebugEvent::Line) {
                if (!haveLine) {
                    info.lineStart = static_cast<ca::u32>(e.line);
                    lastAddr = e.addr;
                    lastLine = e.line;
                    haveLine = true;
                    continue;
                }
                // 地址差 + 行差 → special / AdvancePC+AdvanceLine。
                const ca::u32 addrDiff = e.addr - lastAddr;
                const ca::i32 lineDiff = e.line - lastLine;
                if (addrDiff == 0) {
                    core::DebugOp op;
                    op.opcode = core::kDbgAdvanceLine;
                    op.lineDiff = lineDiff;
                    info.ops.push_back(op);
                } else {
                    const ca::u32 step = addrDiff > 16 ? 16 : addrDiff;
                    const ca::i32 adj = static_cast<ca::i32>(step * 15 + (lineDiff + 4));
                    if (lineDiff >= -4 && lineDiff <= 10 && adj >= 0 &&
                        adj <= 245) {
                        core::DebugOp op;
                        op.opcode = static_cast<ca::u8>(core::kDbgFirstSpecial + adj);
                        // special opcode 的语义字段必须与编码自洽（writeDebugInfo 校验）。
                        op.addressDiff = core::debugSpecialAddressDiff(op.opcode);
                        op.lineDiff = core::debugSpecialLineDiff(op.opcode);
                        info.ops.push_back(op);
                    } else {
                        core::DebugOp pc;
                        pc.opcode = core::kDbgAdvancePc;
                        pc.addressDiff = addrDiff;
                        info.ops.push_back(pc);
                        core::DebugOp ln2;
                        ln2.opcode = core::kDbgAdvanceLine;
                        ln2.lineDiff = lineDiff;
                        info.ops.push_back(ln2);
                    }
                }
                lastAddr = e.addr;
                lastLine = e.line;
                continue;
            }
            core::DebugOp op;
            switch (e.kind) {
            case DebugEvent::LocalStart:
            case DebugEvent::LocalStartExt:
                op.opcode = e.kind == DebugEvent::LocalStart
                                ? core::kDbgStartLocal
                                : core::kDbgStartLocalExtended;
                op.reg = e.reg;
                op.nameIdx = e.nameIdx;
                op.typeIdx = e.typeIdx;
                op.sigIdx = e.sigIdx;
                break;
            case DebugEvent::LocalEnd:
                op.opcode = core::kDbgEndLocal;
                op.reg = e.reg;
                break;
            case DebugEvent::LocalRestart:
                op.opcode = core::kDbgRestartLocal;
                op.reg = e.reg;
                break;
            case DebugEvent::Prologue:
                op.opcode = core::kDbgSetPrologueEnd;
                break;
            case DebugEvent::Epilogue:
                op.opcode = core::kDbgSetEpilogueBegin;
                break;
            default:
                continue;
            }
            info.ops.push_back(op);
            lastAddr = e.addr;
        }
        Result<std::vector<ca::u8>, WriteError> bytes = core::writeDebugInfo(info);
        if (bytes.is_err()) {
            return Err(fail(AsmErrorCode::Overflow, ctx.line, "debug info"));
        }
        out.debugBytes = std::move(bytes).unwrap();
    }

    // 注解项入池 + 挂载。
    if (!ctx.methodAnnotations.empty()) {
        std::vector<ca::u32> pool;
        for (AnnotationItem& item : ctx.methodAnnotations) {
            const Result<ca::u32, ReadError> idx = dex.addAnnotationItem(item);
            if (idx.is_err()) {
                return Err(fail(AsmErrorCode::ModelError, ctx.line, "annotation"));
            }
            pool.push_back(idx.unwrap());
        }
        if (Result<void, ReadError> r =
                dex.setMethodAnnotations(classDefIdx, ctx.methodIdx, pool);
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, ctx.line, "method annotations"));
        }
    }
    if (!ctx.parameterAnnotations.empty()) {
        ca::u32 maxParam = 0;
        for (const auto& e : ctx.parameterAnnotations) {
            maxParam = std::max(maxParam, e.first + 1);
        }
        std::vector<std::vector<ca::u32>> perParam(maxParam);
        for (const auto& e : ctx.parameterAnnotations) {
            for (const AnnotationItem& item : e.second) {
                const Result<ca::u32, ReadError> idx = dex.addAnnotationItem(item);
                if (idx.is_err()) {
                    return Err(fail(AsmErrorCode::ModelError, ctx.line, "annotation"));
                }
                perParam[e.first].push_back(idx.unwrap());
            }
        }
        if (Result<void, ReadError> r = dex.setParameterAnnotations(
                classDefIdx, ctx.methodIdx, perParam);
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, ctx.line, "param annotations"));
        }
    }

    core::MethodAddition add;
    add.classDefIdx = classDefIdx;
    add.methodIdx = ctx.methodIdx;
    add.accessFlags = ctx.accessFlags;
    add.item = std::move(out.item);
    add.insns = std::move(out.insns);
    add.debugInfo = std::move(out.debugBytes);
    self.options().methodAdditions.push_back(std::move(add));
    return Ok();
}

}   // namespace

Result<ca::u32, AsmError> SmaliAssembler::assembleClass(std::string_view text)
{
    // 行切分。
    std::vector<std::string> lines;
    std::vector<ca::u32> lineNos;
    {
        std::string cur;
        ca::u32 lineNo = 1;
        for (char c : text) {
            if (c == '\n') {
                lines.push_back(cur);
                lineNos.push_back(lineNo++);
                cur.clear();
            } else if (c != '\r') {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) {
            lines.push_back(cur);
            lineNos.push_back(lineNo);
        }
    }

    ca::u32 classIdx = 0;
    ca::u32 classFlags = 0;
    bool haveClass = false;
    std::vector<ca::u32> interfaces;
    bool pushed = false;
    ca::u32 classDefIdx = 0;
    std::vector<ca::u32> classAnnotationPool;
    struct PendingField
    {
        ca::u32 fieldIdx;
        bool isStatic;
        std::string valueText;  // 空 = 无初值
    };
    std::vector<PendingField> pendingFields;

    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string raw = lines[i];
        const ca::u32 ln = lineNos.empty() ? 0 : lineNos[i];
        const std::string t = trimTok(raw);
        if (t.empty() || t[0] == '#') {
            continue;
        }
        const std::vector<std::string> toks = tokenize(t);
        const std::string& d = toks[0];

        if (d == ".class") {
            if (toks.size() < 2) {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            ca::u32 classFlagsTmp = 0;
            std::size_t fi = 1;
            while (fi < toks.size() && accessFlagOf(toks[fi]).has_value()) {
                classFlagsTmp |= *accessFlagOf(toks[fi]);
                ++fi;
            }
            classFlags = classFlagsTmp;
            const std::string& desc = toks[fi];
            const Result<ca::u32, core::ReadError> idx = dex_.addType(desc);
            if (idx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, ln, desc));
            }
            classIdx = idx.unwrap();
            haveClass = true;
            continue;
        }
        if (d == ".super") {
            if (!haveClass) {
                return Err(fail(AsmErrorCode::Syntax, ln, ".super before .class"));
            }
            if (toks.size() != 2) {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            const Result<ca::u32, core::ReadError> idx = dex_.addType(toks[1]);
            if (idx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, ln, toks[1]));
            }
            superclassIdx_ = idx.unwrap();
            continue;
        }
        if (d == ".source") {
            if (toks.size() != 2 || toks[1].size() < 2 ||
                toks[1].front() != '"' || toks[1].back() != '"') {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            R<ca::u32> idx = internString(dex_, toks[1].substr(1, toks[1].size() - 2), ln);
            if (idx.is_err()) {
                return Err(idx.unwrap_err());
            }
            sourceFileIdx_ = idx.unwrap();
            continue;
        }
        if (d == ".implements") {
            if (toks.size() != 2) {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            const Result<ca::u32, core::ReadError> idx = dex_.addType(toks[1]);
            if (idx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, ln, toks[1]));
            }
            interfaces.push_back(idx.unwrap());
            continue;
        }
        if (d == ".field") {
            std::size_t k = 1;
            ca::u32 flags = 0;
            while (k < toks.size() && accessFlagOf(toks[k]).has_value()) {
                flags |= *accessFlagOf(toks[k]);
                ++k;
            }
            if (k >= toks.size()) {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            const std::string& nt = toks[k];
            const std::size_t colon = nt.rfind(':');
            if (colon == std::string::npos) {
                return Err(fail(AsmErrorCode::Syntax, ln, t));
            }
            const std::string name = nt.substr(0, colon);
            const std::string typeDesc = nt.substr(colon + 1);
            const Result<ca::u32, core::ReadError> typeIdx = dex_.addType(typeDesc);
            if (typeIdx.is_err()) {
                return Err(fail(AsmErrorCode::BadRef, ln, typeDesc));
            }
            R<ca::u32> nameIdx = internString(dex_, name, ln);
            if (nameIdx.is_err()) {
                return Err(nameIdx.unwrap_err());
            }
            const Result<ca::u32, core::ReadError> fieldIdx = dex_.addField(
                static_cast<ca::u16>(classIdx), static_cast<ca::u16>(typeIdx.unwrap()),
                nameIdx.unwrap());
            if (fieldIdx.is_err()) {
                return Err(fail(AsmErrorCode::ModelError, ln, "addField"));
            }
            PendingField pf;
            pf.fieldIdx = fieldIdx.unwrap();
            pf.isStatic = (flags & 0x8) != 0;
            // 初值：`= value`（可能跨 token）。
            const std::size_t eq = t.find('=');
            if (eq != std::string::npos) {
                pf.valueText = t.substr(eq + 1);
            }
            pendingFields.push_back(pf);

            core::FieldAddition add;
            add.classDefIdx = pushed ? classDefIdx : 0;
            add.fieldIdx = pf.fieldIdx;
            add.accessFlags = flags;
            add.isStatic = pf.isStatic;
            // classDefIdx 在类体解析完才知道；先记原始编辑，push 后回填。
            if (pushed) {
                options_.fieldAdditions.push_back(add);
            } else {
                deferredFieldAdditions_.push_back(add);
            }
            // 字段注解（.annotation 块紧跟字段）。
            std::vector<ca::u32> pool;
            while (i + 1 < lines.size() &&
                   trimTok(lines[i + 1]).compare(0, 11, ".annotation") == 0) {
                ++i;
                std::string acc = trimTok(lines[i]);
                if (acc.find(".end annotation") == std::string::npos) {
                    while (i + 1 < lines.size() &&
                           trimTok(lines[i + 1]) != ".end annotation") {
                        acc += " " + trimTok(lines[++i]);
                    }
                    ++i;  // .end annotation；单行时终结符在行内，不多吃
                }
                const std::size_t sp1 = acc.find(' ');
                const std::size_t sp2 = acc.find(' ', sp1 + 1);
                const std::string vis = acc.substr(sp1 + 1, sp2 - sp1 - 1);
                const std::size_t typeStart = sp2 + 1;
                const std::size_t typeEnd = acc.find(' ', typeStart);
                const std::string typeDesc =
                    acc.substr(typeStart, typeEnd == std::string::npos
                                              ? std::string::npos
                                              : typeEnd - typeStart);
                std::string valueText =
                    typeEnd == std::string::npos ? "" : acc.substr(typeEnd);
                    valueText = stripEndAnnotation(std::move(valueText));
                R<EncodedValue> v = parseValue(
                    dex_, ".subannotation " + typeDesc + valueText + " .end subannotation",
                    ln);
                if (v.is_err()) {
                    return Err(v.unwrap_err());
                }
                EncodedValue val = std::move(v).unwrap();
                AnnotationItem item;
                item.visibility = vis == "runtime" ? 1 : (vis == "system" ? 2 : 0);
                item.annotation = std::move(*val.annotation);
                const Result<ca::u32, core::ReadError> poolIdx = dex_.addAnnotationItem(item);
                if (poolIdx.is_err()) {
                    return Err(fail(AsmErrorCode::ModelError, ln, "annotation"));
                }
                pool.push_back(poolIdx.unwrap());
            }
            if (!pool.empty()) {
                deferredFieldAnnotations_.emplace_back(pf.fieldIdx, std::move(pool));
            }
            continue;
        }
        if (d == ".annotation") {
            std::string acc = t;
            if (acc.find(".end annotation") == std::string::npos) {
                while (i + 1 < lines.size() &&
                       trimTok(lines[i + 1]) != ".end annotation") {
                    acc += " " + trimTok(lines[++i]);
                }
                ++i;  // 单行时终结符在行内，不多吃
            }
            const std::size_t sp1 = acc.find(' ');
            const std::size_t sp2 = acc.find(' ', sp1 + 1);
            const std::string vis = acc.substr(sp1 + 1, sp2 - sp1 - 1);
            const std::size_t typeStart = sp2 + 1;
            const std::size_t typeEnd = acc.find(' ', typeStart);
            const std::string typeDesc =
                acc.substr(typeStart, typeEnd == std::string::npos
                                          ? std::string::npos
                                          : typeEnd - typeStart);
            std::string valueText =
                typeEnd == std::string::npos ? "" : acc.substr(typeEnd);
                valueText = stripEndAnnotation(std::move(valueText));
            const std::size_t endAnn = valueText.find(".end annotation");
            if (endAnn != std::string::npos) {
                valueText = valueText.substr(0, endAnn);
            }
            R<EncodedValue> v = parseValue(
                dex_, ".subannotation " + typeDesc + valueText + " .end subannotation",
                ln);
            if (v.is_err()) {
                return Err(v.unwrap_err());
            }
            EncodedValue val = std::move(v).unwrap();
            AnnotationItem item;
            item.visibility = vis == "runtime" ? 1 : (vis == "system" ? 2 : 0);
            item.annotation = std::move(*val.annotation);
            const Result<ca::u32, core::ReadError> poolIdx = dex_.addAnnotationItem(item);
            if (poolIdx.is_err()) {
                return Err(fail(AsmErrorCode::ModelError, ln, "annotation"));
            }
            classAnnotationPool.push_back(poolIdx.unwrap());
            continue;
        }
        if (d == ".method") {
            if (!haveClass) {
                return Err(fail(AsmErrorCode::Syntax, ln, ".method before .class"));
            }
            if (!pushed) {
                core::ClassDef def;
                def.classIdx = classIdx;
                def.accessFlags = classFlags;
                def.superclassIdx = superclassIdx_;
                def.sourceFileIdx = sourceFileIdx_;
                dex_.classDefs.push_back(def);
                classDefIdx = static_cast<ca::u32>(dex_.classDefs.size() - 1);
                pushed = true;
                for (core::FieldAddition& fa : deferredFieldAdditions_) {
                    fa.classDefIdx = classDefIdx;
                    options_.fieldAdditions.push_back(fa);
                }
                deferredFieldAdditions_.clear();
            }
            // 收集到 .end method。
            std::vector<std::string> body;
            std::vector<ca::u32> bodyNos;
            while (i + 1 < lines.size() && trimTok(lines[i + 1]) != ".end method") {
                ++i;
                const std::string b = trimTok(lines[i]);
                if (b.empty() || b[0] == '#') {
                    continue;
                }
                body.push_back(b);
                bodyNos.push_back(lineNos[i]);
            }
            if (i + 1 >= lines.size()) {
                return Err(fail(AsmErrorCode::Syntax, ln, "unterminated .method"));
            }
            ++i;  // .end method
            if (Result<void, AsmError> r =
                    assembleMethod(dex_, *this, t, body, bodyNos, classDefIdx, classIdx);
                r.is_err()) {
                return Err(r.unwrap_err());
            }
            continue;
        }
        return Err(fail(AsmErrorCode::UnknownDirective, ln, d));
    }

    if (!haveClass) {
        return Err(fail(AsmErrorCode::Syntax, 0, "no .class directive"));
    }
    if (!pushed) {
        core::ClassDef def;
        def.classIdx = classIdx;
        def.accessFlags = classFlags;
        def.superclassIdx = superclassIdx_;
        def.sourceFileIdx = sourceFileIdx_;
        dex_.classDefs.push_back(def);
        classDefIdx = static_cast<ca::u32>(dex_.classDefs.size() - 1);
        pushed = true;
        for (core::FieldAddition& fa : deferredFieldAdditions_) {
            fa.classDefIdx = classDefIdx;
            options_.fieldAdditions.push_back(fa);
        }
        deferredFieldAdditions_.clear();
    }

    // 接口与静态初值（需要 classDefIdx / 已注入的字段）。
    if (!interfaces.empty()) {
        if (Result<void, core::ReadError> r = dex_.setClassInterfaces(classDefIdx, interfaces);
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, 0, "interfaces"));
        }
    }
    for (PendingField& pf : pendingFields) {
        if (!pf.isStatic || pf.valueText.empty()) {
            continue;
        }
        R<EncodedValue> v = parseValue(dex_, pf.valueText, 0);
        if (v.is_err()) {
            return Err(v.unwrap_err());
        }
        if (Result<void, core::ReadError> r = dex_.setStaticFieldValue(
                classDefIdx, pf.fieldIdx, std::move(v).unwrap());
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, 0, "static value"));
        }
    }
    if (!classAnnotationPool.empty()) {
        if (Result<void, core::ReadError> r =
                dex_.setClassAnnotations(classDefIdx, classAnnotationPool);
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, 0, "class annotations"));
        }
    }
    for (auto& [fieldIdx, pool] : deferredFieldAnnotations_) {
        if (Result<void, core::ReadError> r =
                dex_.setFieldAnnotations(classDefIdx, fieldIdx, pool);
            r.is_err()) {
            return Err(fail(AsmErrorCode::ModelError, 0, "field annotations"));
        }
    }
    deferredFieldAnnotations_.clear();
    return Ok(classDefIdx);
}

}   // namespace dex::smali
