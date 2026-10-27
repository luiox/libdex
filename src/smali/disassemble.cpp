#include "smali/disassemble.hpp"
/// @file        disassemble.cpp
/// @brief       libsmali 反汇编器实现。
#include "smali/disassemble.hpp"

#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "jstr/conversion.hpp"

#include "dex/core/annotation.hpp"
#include "dex/core/code_item.hpp"
#include "dex/core/debug_info.hpp"
#include "dex/core/encoded_value.hpp"
#include "dex/core/insn.hpp"
#include "smali/opcodes.hpp"

namespace dex::smali {

using core::AnnotationItem;
using core::AnnotationSetItem;
using core::AnnotationsDirectory;
using core::ByteSlice;
using core::ClassData;
using core::CodeItem;
using core::DexFile;
using core::EncodedAnnotation;
using core::EncodedValue;
using core::Insn;
using core::DebugInfo;
using core::Ok;
using core::Err;

const char* to_string(SmaliError e) noexcept
{
    switch (e) {
    case SmaliError::Ok: return "ok";
    case SmaliError::BadIndex: return "bad index";
    case SmaliError::SourceUnreadable: return "source unreadable";
    case SmaliError::Unencodable: return "not representable in smali text";
    }
    return "unknown";
}

namespace {

constexpr int kIndentUnit = 4;

std::string ind(int level)
{
    const int n = level * kIndentUnit > 64 ? 64 : level * kIndentUnit;
    return std::string(static_cast<std::size_t>(n), ' ');
}

SmaliError fromRead(core::ReadError e) noexcept
{
    return e == core::ReadError::BadIndex ? SmaliError::BadIndex
                                          : SmaliError::SourceUnreadable;
}

/// @brief MUTF-8 字符串 → UTF-8 文本（不经转义）。
Result<std::string, SmaliError> toText(DexFile& dex, ca::u32 stringIdx)
{
    const Result<jstr::MUtf8StringRef, core::ReadError> s = dex.string(stringIdx);
    if (s.is_err()) {
        return Err(fromRead(s.unwrap_err()));
    }
    const Result<std::u16string, jstr::EncodingError> u16 =
        jstr::mutf8_to_utf16(s.unwrap());
    if (u16.is_err()) {
        return Err(SmaliError::SourceUnreadable);
    }
    std::string out;
    out.reserve(u16.unwrap().size());
    for (char16_t c : u16.unwrap()) {
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return Ok(std::move(out));
}

/// @brief smali 字符串字面量（带引号与转义）。
Result<std::string, SmaliError> quotedString(DexFile& dex, ca::u32 stringIdx)
{
    const Result<std::string, SmaliError> text = toText(dex, stringIdx);
    if (text.is_err()) {
        return text;
    }
    std::string out = "\"";
    for (unsigned char c : text.unwrap()) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20 || c >= 0x7F) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    out += "\"";
    return Ok(std::move(out));
}

Result<std::string, SmaliError> typeText(DexFile& dex, ca::u32 typeIdx)
{
    const Result<jstr::MUtf8StringRef, core::ReadError> d = dex.typeDescriptor(typeIdx);
    if (d.is_err()) {
        return Err(fromRead(d.unwrap_err()));
    }
    return Ok(std::string(d.unwrap().as_std_view()));
}

Result<std::string, SmaliError> fieldRef(DexFile& dex, ca::u32 fieldIdx)
{
    if (fieldIdx >= dex.fieldCount()) {
        return Err(SmaliError::BadIndex);
    }
    const core::FieldId& f = dex.fieldIds[fieldIdx];
    const Result<std::string, SmaliError> cls = typeText(dex, f.classIdx);
    const Result<std::string, SmaliError> type = typeText(dex, f.typeIdx);
    const Result<std::string, SmaliError> name = toText(dex, f.nameIdx);
    if (cls.is_err() || type.is_err() || name.is_err()) {
        return Err(cls.is_err() ? cls.unwrap_err()
                                : (type.is_err() ? type.unwrap_err() : name.unwrap_err()));
    }
    return Ok(cls.unwrap() + "->" + name.unwrap() + ":" + type.unwrap());
}

Result<std::vector<std::string>, SmaliError> protoParamTexts(DexFile& dex,
                                                             ca::u32 protoIdx)
{
    std::vector<std::string> out;
    const Result<core::TypeListSpan, core::ReadError> params =
        dex.protoParameters(protoIdx);
    if (params.is_err()) {
        return Err(fromRead(params.unwrap_err()));
    }
    const core::TypeListSpan& span = params.unwrap();
    for (ca::u32 i = 0; i < span.size; ++i) {
        const Result<std::string, SmaliError> t = typeText(dex, span.at(i));
        if (t.is_err()) {
            return Err(t.unwrap_err());
        }
        out.push_back(std::move(t).unwrap());
    }
    return Ok(std::move(out));
}

Result<std::string, SmaliError> protoText(DexFile& dex, ca::u32 protoIdx)
{
    if (protoIdx >= dex.protoCount()) {
        return Err(SmaliError::BadIndex);
    }
    const core::ProtoId& p = dex.protoIds[protoIdx];
    const Result<std::string, SmaliError> ret = typeText(dex, p.returnTypeIdx);
    if (ret.is_err()) {
        return ret;
    }
    const Result<std::vector<std::string>, SmaliError> params =
        protoParamTexts(dex, protoIdx);
    if (params.is_err()) {
        return params.unwrap_err();
    }
    std::string out = "(";
    for (const std::string& t : params.unwrap()) {
        out += t;
    }
    out += ")" + ret.unwrap();
    return Ok(std::move(out));
}

Result<std::string, SmaliError> methodRef(DexFile& dex, ca::u32 methodIdx)
{
    if (methodIdx >= dex.methodCount()) {
        return Err(SmaliError::BadIndex);
    }
    const core::MethodId& m = dex.methodIds[methodIdx];
    const Result<std::string, SmaliError> cls = typeText(dex, m.classIdx);
    const Result<std::string, SmaliError> name = toText(dex, m.nameIdx);
    const Result<std::string, SmaliError> proto = protoText(dex, m.protoIdx);
    if (cls.is_err() || name.is_err() || proto.is_err()) {
        return Err(cls.is_err() ? cls.unwrap_err()
                                : (name.is_err() ? name.unwrap_err()
                                                 : proto.unwrap_err()));
    }
    return Ok(cls.unwrap() + "->" + name.unwrap() + proto.unwrap());
}

// ---- encoded_value 渲染 ----

Result<std::string, SmaliError> valueText(DexFile& dex, const EncodedValue& v,
                                          int depth);

Result<std::string, SmaliError> annotationBody(DexFile& dex,
                                               const EncodedAnnotation& a, int depth)
{
    const Result<std::string, SmaliError> type = typeText(dex, a.typeIdx);
    if (type.is_err()) {
        return type;
    }
    std::string out = type.unwrap();
    for (const core::AnnotationElement& e : a.elements) {
        const Result<std::string, SmaliError> name = toText(dex, e.nameIdx);
        if (name.is_err()) {
            return name;
        }
        const Result<std::string, SmaliError> v = valueText(dex, e.value, depth + 1);
        if (v.is_err()) {
            return v;
        }
        out += " " + name.unwrap() + " = " + v.unwrap();
    }
    return Ok(std::move(out));
}

Result<std::string, SmaliError> valueText(DexFile& dex, const EncodedValue& v,
                                          int depth)
{
    if (depth > 32) {
        return Err(SmaliError::Unencodable);
    }
    char buf[32];
    switch (v.type) {
    case core::EncodedValueType::Byte:
    case core::EncodedValueType::Short:
    case core::EncodedValueType::Int:
    case core::EncodedValueType::Long:
        std::snprintf(buf, sizeof(buf), "%lld",
                      static_cast<long long>(v.integer));
        return Ok(std::string(buf));
    case core::EncodedValueType::Char:
        std::snprintf(buf, sizeof(buf), "'\\u%04x'", v.bits & 0xFFFFu);
        return Ok(std::string(buf));
    case core::EncodedValueType::Float:
        std::snprintf(buf, sizeof(buf), "0x%08xF", static_cast<ca::u32>(v.bits));
        return Ok(std::string(buf));
    case core::EncodedValueType::Double:
        std::snprintf(buf, sizeof(buf), "0x%016llxD",
                      static_cast<unsigned long long>(v.bits));
        return Ok(std::string(buf));
    case core::EncodedValueType::String:
        return quotedString(dex, v.index);
    case core::EncodedValueType::Type:
        return typeText(dex, v.index);
    case core::EncodedValueType::Field:
        return fieldRef(dex, v.index);
    case core::EncodedValueType::Method:
        return methodRef(dex, v.index);
    case core::EncodedValueType::Enum: {
        const Result<std::string, SmaliError> r = fieldRef(dex, v.index);
        if (r.is_err()) {
            return r;
        }
        return Ok(".enum " + r.unwrap());
    }
    case core::EncodedValueType::MethodType: {
        const Result<std::string, SmaliError> r = protoText(dex, v.index);
        if (r.is_err()) {
            return r;
        }
        return Ok("method-type " + r.unwrap());
    }
    case core::EncodedValueType::MethodHandle:
        std::snprintf(buf, sizeof(buf), "method-handle@%u", v.index);
        return Ok(std::string(buf));
    case core::EncodedValueType::Null:
        return Ok(std::string("null"));
    case core::EncodedValueType::Boolean:
        return Ok(std::string(v.boolean ? "true" : "false"));
    case core::EncodedValueType::Array: {
        std::string out = "{";
        bool first = true;
        for (const EncodedValue& e : v.array) {
            const Result<std::string, SmaliError> t = valueText(dex, e, depth + 1);
            if (t.is_err()) {
                return t;
            }
            if (!first) {
                out += ",";
            }
            first = false;
            out += " " + t.unwrap();
        }
        out += " }";
        return Ok(std::move(out));
    }
    case core::EncodedValueType::Annotation: {
        if (v.annotation == nullptr) {
            return Err(SmaliError::Unencodable);
        }
        const Result<std::string, SmaliError> body =
            annotationBody(dex, *v.annotation, depth);
        if (body.is_err()) {
            return body;
        }
        return Ok(".subannotation " + body.unwrap() + " .end subannotation");
    }
    }
    return Err(SmaliError::Unencodable);
}

// ---- 注解块渲染 ----

const char* visibilityName(ca::u8 visibility)
{
    switch (static_cast<core::AnnotationVisibility>(visibility)) {
    case core::AnnotationVisibility::Build: return "build";
    case core::AnnotationVisibility::Runtime: return "runtime";
    case core::AnnotationVisibility::System: return "system";
    }
    return "unknown";
}

Result<void, SmaliError> annotationBlock(DexFile& dex, const AnnotationItem& item,
                                         int level, std::string& out)
{
    const Result<std::string, SmaliError> body =
        annotationBody(dex, item.annotation, 0);
    if (body.is_err()) {
        return Err(body.unwrap_err());
    }
    out += ind(level);
    out += ".annotation ";
    out += visibilityName(item.visibility);
    out += ' ';
    out += body.unwrap();
    out += " .end annotation\n";
    return Ok();
}

/// @brief 一组注解项（池或源偏移）渲染为多行块。
template <typename Items>
Result<void, SmaliError> annotationBlocks(DexFile& dex, const Items& itemOffs,
                                          int level, std::string& out)
{
    for (const ca::u32 off : itemOffs) {
        const Result<const AnnotationItem*, core::ReadError> item =
            dex.annotationItem(off);
        if (item.is_err()) {
            return Err(fromRead(item.unwrap_err()));
        }
        if (Result<void, SmaliError> r = annotationBlock(dex, *item.unwrap(), level, out);
            r.is_err()) {
            return Err(r.unwrap_err());
        }
    }
    return Ok();
}

// ---- 指令渲染 ----

struct LabelTable
{
    std::unordered_map<ca::u32, std::string> byAddr;

    const std::string& at(ca::u32 addr)
    {
        auto found = byAddr.find(addr);
        if (found == byAddr.end()) {
            char buf[24];
            std::snprintf(buf, sizeof(buf), ":l%u", addr);
            found = byAddr.emplace(addr, buf).first;
        }
        return found->second;
    }
};

std::string regText(ca::u16 reg, ca::u32 firstParamReg)
{
    char buf[16];
    if (reg >= firstParamReg) {
        std::snprintf(buf, sizeof(buf), "p%u", reg - firstParamReg);
    } else {
        std::snprintf(buf, sizeof(buf), "v%u", reg);
    }
    return buf;
}

std::string literalText(ca::i64 literal, core::InsnFormat format)
{
    char buf[32];
    if (format == core::InsnFormat::F21h) {
        // 已移位的 high16：按位模式十六进制渲染，保证无歧义。
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(literal));
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(literal));
    return buf;
}

Result<std::string, SmaliError> indexText(DexFile& dex, const Insn& i)
{
    switch (i.indexKind) {
    case core::IndexKind::String:
        return quotedString(dex, i.index);
    case core::IndexKind::Type:
        return typeText(dex, i.index);
    case core::IndexKind::Field:
        return fieldRef(dex, i.index);
    case core::IndexKind::Method:
        return methodRef(dex, i.index);
    case core::IndexKind::Proto:
        return protoText(dex, i.index);
    case core::IndexKind::CallSite:
    case core::IndexKind::MethodHandle: {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "@%u", i.index);
        return Ok(std::string(buf));
    }
    default:
        return Err(SmaliError::Unencodable);
    }
}

/// @brief 渲染一条非 payload 指令（不含 label 行）。
Result<std::string, SmaliError> insnText(DexFile& dex, const Insn& i,
                                         LabelTable& labels, ca::u32 firstParamReg)
{
    const std::optional<Mnemonic> m = mnemonicOf(i.opcode);
    if (!m || m->format != i.format) {
        return Err(SmaliError::Unencodable);
    }
    std::string out = m->name;
    const auto reg = [&](ca::u16 r) { return regText(r, firstParamReg); };
    const auto push = [&](const std::string& s) { out += " " + s; };

    switch (i.format) {
    case core::InsnFormat::F10x:
        break;
    case core::InsnFormat::F12x:
        push(reg(i.registers[0]));
        push(reg(i.registers[1]));
        break;
    case core::InsnFormat::F11x:
        push(reg(i.registers[0]));
        break;
    case core::InsnFormat::F11n:
        push(reg(i.registers[0]));
        push(literalText(i.literal, i.format));
        break;
    case core::InsnFormat::F21s:
    case core::InsnFormat::F21h:
    case core::InsnFormat::F31i:
    case core::InsnFormat::F51l:
        push(reg(i.registers[0]));
        push(literalText(i.literal, i.format));
        break;
    case core::InsnFormat::F21c:
    case core::InsnFormat::F31c: {
        push(reg(i.registers[0]));
        const Result<std::string, SmaliError> r = indexText(dex, i);
        if (r.is_err()) {
            return r;
        }
        push(r.unwrap());
        break;
    }
    case core::InsnFormat::F23x:
        push(reg(i.registers[0]));
        push(reg(i.registers[1]));
        push(reg(i.registers[2]));
        break;
    case core::InsnFormat::F22b:
    case core::InsnFormat::F22s:
        push(reg(i.registers[0]));
        push(reg(i.registers[1]));
        push(literalText(i.literal, i.format));
        break;
    case core::InsnFormat::F22c: {
        push(reg(i.registers[0]));
        push(reg(i.registers[1]));
        const Result<std::string, SmaliError> r = indexText(dex, i);
        if (r.is_err()) {
            return r;
        }
        push(r.unwrap());
        break;
    }
    case core::InsnFormat::F22x:
        push(reg(i.registers[0]));
        push(reg(i.startRegister));
        break;
    case core::InsnFormat::F32x:
        push(reg(i.registers[0]));
        push(reg(i.startRegister));
        break;
    case core::InsnFormat::F10t:
    case core::InsnFormat::F20t:
    case core::InsnFormat::F30t:
    case core::InsnFormat::F21t:
    case core::InsnFormat::F22t:
        if (i.format == core::InsnFormat::F21t || i.format == core::InsnFormat::F22t) {
            push(reg(i.registers[0]));
            if (i.format == core::InsnFormat::F22t) {
                push(reg(i.registers[1]));
            }
        }
        push(labels.at(insnBranchTarget(i)));
        break;
    case core::InsnFormat::F31t:
        push(reg(i.registers[0]));
        push(labels.at(insnBranchTarget(i)));
        break;
    case core::InsnFormat::F35c:
    case core::InsnFormat::F3rc:
    case core::InsnFormat::F45cc:
    case core::InsnFormat::F4rcc: {
        std::string regs = "{";
        if (i.format == core::InsnFormat::F3rc || i.format == core::InsnFormat::F4rcc) {
            if (i.registerCount > 0) {
                regs += reg(i.startRegister) + " .. " +
                        reg(static_cast<ca::u16>(i.startRegister + i.registerCount - 1));
            }
        } else {
            for (ca::u32 k = 0; k < i.registerCount; ++k) {
                if (k != 0) {
                    regs += ", ";
                }
                regs += reg(i.registers[k]);
            }
        }
        regs += "}";
        push(regs);
        const Result<std::string, SmaliError> r = indexText(dex, i);
        if (r.is_err()) {
            return r;
        }
        push(r.unwrap());
        if (i.hasProtoIndex) {
            const Result<std::string, SmaliError> p = protoText(dex, i.protoIndex);
            if (p.is_err()) {
                return p;
            }
            push(p.unwrap());
        }
        break;
    }
    default:
        return Err(SmaliError::Unencodable);
    }
    return Ok(std::move(out));
}

// ---- debug 投影 ----

struct DebugProjection
{
    std::map<ca::u32, ca::i32> lineAt;      ///< addr → 行号
    struct LocalEvent
    {
        ca::u32 addr;
        ca::u32 reg;
        ca::u32 nameIdx = 0;
        ca::u32 typeIdx = 0;
        ca::u32 sigIdx = 0;
        enum Kind { Start, StartExt, End, Restart } kind;
    };
    std::vector<LocalEvent> locals;
    bool prologue = false;
    bool epilogue = false;
    std::vector<std::string> params;        ///< 头部参数名（空串 = 无名）
};

Result<DebugProjection, SmaliError> projectDebug(DexFile& dex,
                                                 const core::DebugInfo& info)
{
    DebugProjection p;
    ca::u32 addr = 0;
    ca::i32 line = static_cast<ca::i32>(info.lineStart);
    p.lineAt[0] = line;
    p.params.reserve(info.parameterNames.size());
    for (ca::u32 idx : info.parameterNames) {
        if (idx == DexFile::kNoIndex) {
            p.params.emplace_back();
            continue;
        }
        const Result<std::string, SmaliError> n = toText(dex, idx);
        if (n.is_err()) {
            return Err(n.unwrap_err());
        }
        p.params.push_back(std::move(n).unwrap());
    }
    for (const core::DebugOp& op : info.ops) {
        if (op.isSpecial()) {
            addr += core::debugSpecialAddressDiff(op.opcode);
            line += core::debugSpecialLineDiff(op.opcode);
            p.lineAt[addr] = line;
            continue;
        }
        switch (op.opcode) {
        case core::kDbgAdvancePc:
            addr += op.addressDiff;
            break;
        case core::kDbgAdvanceLine:
            line += op.lineDiff;
            p.lineAt[addr] = line;
            break;
        case core::kDbgStartLocal:
            p.locals.push_back({addr, op.reg, op.nameIdx, op.typeIdx, 0,
                                DebugProjection::LocalEvent::Start});
            break;
        case core::kDbgStartLocalExtended:
            p.locals.push_back({addr, op.reg, op.nameIdx, op.typeIdx, op.sigIdx,
                                DebugProjection::LocalEvent::StartExt});
            break;
        case core::kDbgEndLocal:
            p.locals.push_back({addr, op.reg, 0, 0, 0,
                                DebugProjection::LocalEvent::End});
            break;
        case core::kDbgRestartLocal:
            p.locals.push_back({addr, op.reg, 0, 0, 0,
                                DebugProjection::LocalEvent::Restart});
            break;
        case core::kDbgSetPrologueEnd:
            p.prologue = true;
            break;
        case core::kDbgSetEpilogueBegin:
            p.epilogue = true;
            break;
        default:
            break;
        }
    }
    return Ok(std::move(p));
}

// ---- 方法渲染 ----

Result<void, SmaliError> renderMethod(DexFile& dex, ca::u32 classDefIdx,
                                      const core::ClassDef& def,
                                      const core::EncodedMethod& method,
                                      std::string& out)
{
    if (method.methodIndex >= dex.methodCount()) {
        return Err(SmaliError::BadIndex);
    }
    const core::MethodId& mid = dex.methodIds[method.methodIndex];
    const Result<std::string, SmaliError> name = toText(dex, mid.nameIdx);
    if (name.is_err()) {
        return Err(name.unwrap_err());
    }
    const Result<std::string, SmaliError> proto = protoText(dex, mid.protoIdx);
    if (proto.is_err()) {
        return Err(proto.unwrap_err());
    }
    out += "\n";
    out += ind(1);
    out += ".method " + renderAccessFlags(method.accessFlags) + " " + name.unwrap() +
           " " + proto.unwrap() + "\n";

    const Result<const CodeItem*, core::ReadError> code = dex.codeItem(method.codeOff);
    if (code.is_err()) {
        return Err(fromRead(code.unwrap_err()));
    }
    const CodeItem* item = code.unwrap();
    if (item == nullptr) {
        out += ind(2) + ".registers 0\n";
        out += ind(1) + ".end method\n";
        return Ok();
    }

    out += ind(2) + ".registers " + std::to_string(item->registersSize) + "\n";

    // debug 头部投影（.params / .prologue / .epilogue）。
    // debugInfo 的指针归 DexFile 的 lazy 缓存所有——绝不能包进本地
    // unique_ptr，否则缓存条目被提前释放（双重析构）。
    const core::DebugInfo* info = nullptr;
    if (item->debugInfoOff != 0) {
        const Result<const core::DebugInfo*, core::ReadError> decoded =
            dex.debugInfo(item->debugInfoOff);
        if (decoded.is_err()) {
            return Err(fromRead(decoded.unwrap_err()));
        }
        info = decoded.unwrap();
    }
    DebugProjection projection;
    const DebugProjection* dbgPtr = nullptr;
    if (info != nullptr) {
        Result<DebugProjection, SmaliError> p = projectDebug(dex, *info);
        if (p.is_err()) {
            return Err(p.unwrap_err());
        }
        projection = std::move(p).unwrap();
        dbgPtr = &projection;
        if (!projection.params.empty()) {
            out += ind(2) + ".params";
            for (const std::string& n : projection.params) {
                out += " \"" + n + "\"";
            }
            out += "\n";
        }
        if (projection.prologue) {
            out += ind(2) + ".prologue\n";
        }
        if (projection.epilogue) {
            out += ind(2) + ".epilogue\n";
        }
    }

    const ca::u32 firstParamReg =
        static_cast<ca::u32>(item->registersSize) - item->insSize;

    // 指令流与 label 表。
    const Result<std::vector<Insn>, core::InsnError> decoded = core::decodeInsns(
        core::subOrEmpty(dex.source(), item->insns.offset, item->insns.length));
    if (decoded.is_err()) {
        return Err(SmaliError::SourceUnreadable);
    }
    const std::vector<Insn>& insns = decoded.unwrap();
    LabelTable labels;
    for (const Insn& i : insns) {
        if (i.isBranch() && i.format != core::InsnFormat::F31t) {
            labels.at(static_cast<ca::u32>(insnBranchTarget(i)));
        } else if (i.format == core::InsnFormat::F31t) {
            labels.at(static_cast<ca::u32>(insnBranchTarget(i)));
        }
    }
    for (const core::TryBlock& b : item->tryBlocks) {
        labels.at(b.startAddress);
        labels.at(static_cast<ca::u32>(b.startAddress) + b.insnCount);
    }
    for (const core::CatchHandler& h : item->catchHandlers) {
        for (const core::TypedCatch& t : h.typed) {
            labels.at(t.address);
        }
        if (h.hasCatchAll) {
            labels.at(h.catchAllAddress);
        }
    }

    // 事件流：debug local/file 事件与指令按地址穿插。
    std::size_t localIdx = 0;
    auto emitLocalEvents = [&](ca::u32 addr) -> Result<void, SmaliError> {
        while (dbgPtr != nullptr && localIdx < dbgPtr->locals.size() &&
               dbgPtr->locals[localIdx].addr <= addr) {
            const DebugProjection::LocalEvent& e = dbgPtr->locals[localIdx];
            out += ind(2);
            switch (e.kind) {
            case DebugProjection::LocalEvent::Start:
            case DebugProjection::LocalEvent::StartExt: {
                const Result<std::string, SmaliError> n =
                    e.nameIdx == DexFile::kNoIndex
                        ? Result<std::string, SmaliError>(Ok(std::string()))
                        : toText(dex, e.nameIdx);
                const Result<std::string, SmaliError> t = typeText(dex, e.typeIdx);
                if (n.is_err() || t.is_err()) {
                    return Err(n.is_err() ? n.unwrap_err() : t.unwrap_err());
                }
                out += (e.kind == DebugProjection::LocalEvent::Start ? ".local "
                                                                     : ".local ");
                out += regText(e.reg, firstParamReg) + ", \"" + n.unwrap() +
                       "\":" + t.unwrap();
                if (e.kind == DebugProjection::LocalEvent::StartExt) {
                    const Result<std::string, SmaliError> sig = toText(dex, e.sigIdx);
                    if (sig.is_err()) {
                        return Err(sig.unwrap_err());
                    }
                    out += ",\"" + sig.unwrap() + "\"";
                }
                out += "\n";
                break;
            }
            case DebugProjection::LocalEvent::End:
                out += std::string(".end local ") + regText(e.reg, firstParamReg) + "\n";
                break;
            case DebugProjection::LocalEvent::Restart:
                out += std::string(".restart local ") +
                       regText(e.reg, firstParamReg) + "\n";
                break;
            }
            ++localIdx;
        }
        return Ok();
    };
    std::size_t insnIdx = 0;
    while (insnIdx < insns.size()) {
        const Insn& i = insns[insnIdx];
        if (Result<void, SmaliError> r = emitLocalEvents(i.address); r.is_err()) {
            return r;
        }
        if (dbgPtr != nullptr) {
            auto line = dbgPtr->lineAt.find(i.address);
            if (line != dbgPtr->lineAt.end()) {
                out += ind(2) + ".line " + std::to_string(line->second) + "\n";
            }
        }
        if (i.isPayload()) {
            out += ind(2) + labels.at(i.address) + "\n";
            switch (i.payloadKind) {
            case core::PayloadKind::PackedSwitch: {
                out += ind(2) + ".packed-switch " +
                       literalText(i.payloadFirstKey, core::InsnFormat::F31i) + "\n";
                for (ca::u32 t = 0; t < i.payloadCount; ++t) {
                    out += ind(3) +
                           labels.at(static_cast<ca::u32>(
                               static_cast<ca::i64>(i.address) +
                               i.packedSwitchTarget(t))) +
                           "\n";
                }
                out += ind(2) + ".end packed-switch\n";
                break;
            }
            case core::PayloadKind::SparseSwitch: {
                out += ind(2) + ".sparse-switch\n";
                for (ca::u32 t = 0; t < i.payloadCount; ++t) {
                    out += ind(3) + literalText(i.sparseSwitchKey(t), core::InsnFormat::F31i) +
                           " -> " +
                           labels.at(static_cast<ca::u32>(
                               static_cast<ca::i64>(i.address) +
                               i.sparseSwitchTarget(t))) +
                           "\n";
                }
                out += ind(2) + ".end sparse-switch\n";
                break;
            }
            case core::PayloadKind::FillArrayData: {
                out += ind(2) + ".fill-array-data\n";
                out += ind(3) + ".array-data " +
                       std::to_string(i.payloadElementWidth) + "\n";
                const ca::u8* data = i.payloadData.data();
                for (ca::u32 b = 0; b < i.payloadData.size(); ++b) {
                    if (b != 0 && b % 8 == 0) {
                        out += "\n" + ind(4);
                    } else if (b != 0) {
                        out += ' ';
                    }
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "0x%02x", data[b]);
                    out += buf;
                }
                out += "\n" + ind(3) + ".end array-data\n";
                out += ind(2) + ".end fill-array-data\n";
                break;
            }
            default:
                break;
            }
            ++insnIdx;
            continue;
        }
        const Result<std::string, SmaliError> text =
            insnText(dex, i, labels, firstParamReg);
        if (text.is_err()) {
            return Err(text.unwrap_err());
        }
        out += ind(2) + text.unwrap() + "\n";
        ++insnIdx;
    }
    if (Result<void, SmaliError> r = emitLocalEvents(0xFFFFFFFFu); r.is_err()) {
        return r;
    }

    // try/catch。
    for (const core::TryBlock& b : item->tryBlocks) {
        const core::CatchHandler& h = item->catchHandlers[b.handlerIndex];
        for (const core::TypedCatch& t : h.typed) {
            const Result<std::string, SmaliError> type = typeText(dex, t.typeIdx);
            if (type.is_err()) {
                return Err(type.unwrap_err());
            }
            out += ind(2) + ".catch " + type.unwrap() + " { " +
                   labels.at(b.startAddress) + " .. " +
                   labels.at(static_cast<ca::u32>(b.startAddress) + b.insnCount) +
                   " } " + labels.at(t.address) + "\n";
        }
        if (h.hasCatchAll) {
            out += ind(2) + ".catchall { " + labels.at(b.startAddress) + " .. " +
                   labels.at(static_cast<ca::u32>(b.startAddress) + b.insnCount) +
                   " } " + labels.at(h.catchAllAddress) + "\n";
        }
    }

    // 方法注解与参数注解：自有覆盖层优先，否则源目录。
    const auto* owned = &dex.annotationAttachments();
    auto ownedIt = std::find_if(
        owned->begin(), owned->end(),
        [&](const auto& pair) {
            return pair.second.methods.count(method.methodIndex) != 0 ||
                   pair.second.parameters.count(method.methodIndex) != 0;
        });
    if (ownedIt != owned->end()) {
        auto mit = ownedIt->second.methods.find(method.methodIndex);
        if (mit != ownedIt->second.methods.end()) {
            if (Result<void, SmaliError> r =
                    annotationBlocks(dex, mit->second, 2, out);
                r.is_err()) {
                return r;
            }
        }
        auto pit = ownedIt->second.parameters.find(method.methodIndex);
        if (pit != ownedIt->second.parameters.end()) {
            for (ca::u32 param = 0; param < pit->second.size(); ++param) {
                for (const ca::u32 poolIdx : pit->second[param]) {
                    out += ind(2) + ".parameter-annotation " +
                           std::to_string(param) + "\n";
                    const Result<const AnnotationItem*, core::ReadError> item =
                        dex.ownedAnnotationItem(poolIdx);
                    if (item.is_err()) {
                        return Err(fromRead(item.unwrap_err()));
                    }
                    if (Result<void, SmaliError> r =
                            annotationBlock(dex, *item.unwrap(), 3, out);
                        r.is_err()) {
                        return r;
                    }
                }
            }
        }
    } else if (def.annotationsOff != 0) {
        const Result<const AnnotationsDirectory*, core::ReadError> dir =
            dex.classAnnotations(classDefIdx);
        if (dir.is_err()) {
            return Err(fromRead(dir.unwrap_err()));
        }
        if (dir.unwrap() != nullptr) {
            for (const core::AnnotationsDirectoryEntry& e :
                 dir.unwrap()->methodAnnotations) {
                if (e.memberIdx != method.methodIndex) {
                    continue;
                }
                const Result<const AnnotationSetItem*, core::ReadError> set =
                    dex.annotationSet(e.annotationsOff);
                if (set.is_err()) {
                    return Err(fromRead(set.unwrap_err()));
                }
                if (Result<void, SmaliError> r = annotationBlocks(
                        dex, set.unwrap()->annotationOffs, 2, out);
                    r.is_err()) {
                    return r;
                }
            }
            for (const core::AnnotationsDirectoryEntry& e :
                 dir.unwrap()->parameterAnnotations) {
                if (e.memberIdx != method.methodIndex) {
                    continue;
                }
                const Result<const core::AnnotationSetRefList*, core::ReadError> refs =
                    dex.annotationSetRefList(e.annotationsOff);
                if (refs.is_err()) {
                    return Err(fromRead(refs.unwrap_err()));
                }
                for (ca::u32 param = 0;
                     param < refs.unwrap()->annotationSetOffs.size(); ++param) {
                    const ca::u32 setOff = refs.unwrap()->annotationSetOffs[param];
                    if (setOff == 0) {
                        continue;
                    }
                    const Result<const AnnotationSetItem*, core::ReadError> set =
                        dex.annotationSet(setOff);
                    if (set.is_err()) {
                        return Err(fromRead(set.unwrap_err()));
                    }
                    for (const ca::u32 itemOff : set.unwrap()->annotationOffs) {
                        out += ind(2) + ".parameter-annotation " +
                               std::to_string(param) + "\n";
                        const Result<const AnnotationItem*, core::ReadError> item =
                            dex.annotationItem(itemOff);
                        if (item.is_err()) {
                            return Err(fromRead(item.unwrap_err()));
                        }
                        if (Result<void, SmaliError> r = annotationBlock(
                                dex, *item.unwrap(), 3, out);
                            r.is_err()) {
                            return Err(r.unwrap_err());
                        }
                    }
                }
            }
        }
    }

    out += ind(1) + ".end method\n";
    return Ok();
}

}   // namespace

Result<std::string, SmaliError> disassembleClass(DexFile& dex, ca::u32 classDefIdx)
{
    if (classDefIdx >= dex.classCount()) {
        return Err(SmaliError::BadIndex);
    }
    const core::ClassDef& def = dex.classDefs[classDefIdx];
    std::string out;

    const Result<std::string, SmaliError> clsName = typeText(dex, def.classIdx);
    if (clsName.is_err()) {
        return clsName;
    }
    out += ".class " + renderAccessFlags(def.accessFlags) + " " + clsName.unwrap() + "\n";
    if (def.superclassIdx != DexFile::kNoIndex) {
        const Result<std::string, SmaliError> super = typeText(dex, def.superclassIdx);
        if (super.is_err()) {
            return super;
        }
        out += ".super " + super.unwrap() + "\n";
    }
    if (def.sourceFileIdx != DexFile::kNoIndex) {
        const Result<std::string, SmaliError> src = quotedString(dex, def.sourceFileIdx);
        if (src.is_err()) {
            return src;
        }
        out += ".source " + src.unwrap() + "\n";
    }
    if (def.interfacesOff != 0 || def.ownedInterfaces) {
        const Result<core::TypeListSpan, core::ReadError> ifaces = dex.interfaces(classDefIdx);
        if (ifaces.is_err()) {
            return Err(fromRead(ifaces.unwrap_err()));
        }
        const core::TypeListSpan& span = ifaces.unwrap();
        for (ca::u32 i = 0; i < span.size; ++i) {
            const Result<std::string, SmaliError> t = typeText(dex, span.at(i));
            if (t.is_err()) {
                return t;
            }
            out += ".implements " + t.unwrap() + "\n";
        }
    }

    // 注解：源目录 + 自有覆盖层（自有优先；本反汇编器不合并两者）。
    const auto* owned = &dex.annotationAttachments();
    const auto ownedIt = owned->find(classDefIdx);
    if (ownedIt != owned->end() && ownedIt->second.hasClass) {
        if (Result<void, SmaliError> r = annotationBlocks(
                dex, ownedIt->second.classItems, 0, out);
            r.is_err()) {
            return Err(r.unwrap_err());
        }
    } else if (def.annotationsOff != 0) {
        const Result<const AnnotationsDirectory*, core::ReadError> dir =
            dex.classAnnotations(classDefIdx);
        if (dir.is_err()) {
            return Err(fromRead(dir.unwrap_err()));
        }
        if (dir.unwrap() != nullptr && dir.unwrap()->classAnnotationsOff != 0) {
            const Result<const AnnotationSetItem*, core::ReadError> set =
                dex.annotationSet(dir.unwrap()->classAnnotationsOff);
            if (set.is_err()) {
                return Err(fromRead(set.unwrap_err()));
            }
            if (Result<void, SmaliError> r = annotationBlocks(dex, set.unwrap()->annotationOffs,
                                                              0, out);
                r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
    }

    out += "\n";

    const Result<const ClassData*, core::ReadError> data = dex.classData(classDefIdx);
    if (data.is_err()) {
        return Err(fromRead(data.unwrap_err()));
    }
    const ClassData* cd = data.unwrap();

    // 静态初值数组（与 staticFields 平行）。
    std::vector<core::EncodedValue> staticValues;
    if (cd != nullptr && def.staticValuesOff != 0) {
        const Result<const core::EncodedArrayItem*, core::ReadError> arr =
            dex.staticValues(classDefIdx);
        if (arr.is_err()) {
            return Err(fromRead(arr.unwrap_err()));
        }
        staticValues = arr.unwrap()->values;
    }

    auto renderField = [&](const core::EncodedField& f, bool isStatic,
                           ca::u32 valueSlot) -> Result<void, SmaliError> {
        const core::FieldId& fid = dex.fieldIds[f.fieldIndex];
        const Result<std::string, SmaliError> name = toText(dex, fid.nameIdx);
        const Result<std::string, SmaliError> type = typeText(dex, fid.typeIdx);
        if (name.is_err() || type.is_err()) {
            return Err(name.is_err() ? name.unwrap_err() : type.unwrap_err());
        }
        (void)valueSlot;
        out += "\n.field " + renderAccessFlags(f.accessFlags) + " " + name.unwrap() +
               ":" + type.unwrap();
        if (isStatic && valueSlot < staticValues.size()) {
            const Result<std::string, SmaliError> v =
                valueText(dex, staticValues[valueSlot], 0);
            if (v.is_err()) {
                return Err(v.unwrap_err());
            }
            out += " = " + v.unwrap();
        }
        out += "\n";
        // 字段注解。
        const auto ownedIt = owned->find(classDefIdx);
        if (ownedIt != owned->end()) {
            auto fit = ownedIt->second.fields.find(f.fieldIndex);
            if (fit != ownedIt->second.fields.end()) {
                if (Result<void, SmaliError> r =
                        annotationBlocks(dex, fit->second, 1, out);
                    r.is_err()) {
                    return r;
                }
            }
        } else if (def.annotationsOff != 0) {
            const Result<const AnnotationsDirectory*, core::ReadError> dir =
                dex.classAnnotations(classDefIdx);
            if (dir.is_err()) {
                return Err(fromRead(dir.unwrap_err()));
            }
            if (dir.unwrap() != nullptr) {
                for (const core::AnnotationsDirectoryEntry& e :
                     dir.unwrap()->fieldAnnotations) {
                    if (e.memberIdx == f.fieldIndex) {
                        const Result<const AnnotationSetItem*, core::ReadError> set =
                            dex.annotationSet(e.annotationsOff);
                        if (set.is_err()) {
                            return Err(fromRead(set.unwrap_err()));
                        }
                        if (Result<void, SmaliError> r = annotationBlocks(
                                dex, set.unwrap()->annotationOffs, 1, out);
                            r.is_err()) {
                            return r;
                        }
                    }
                }
            }
        }
        return Ok();
    };

    if (cd != nullptr) {
        out += "\n# static fields\n";
        for (ca::u32 i = 0; i < cd->staticFields.size(); ++i) {
            if (Result<void, SmaliError> r =
                    renderField(cd->staticFields[i], true, i);
                r.is_err()) {
                return Err(r.unwrap_err());
            }
        }
        out += "\n# instance fields\n";
        for (const core::EncodedField& f : cd->instanceFields) {
            if (Result<void, SmaliError> r = renderField(f, false, 0); r.is_err()) {
                return Err(r.unwrap_err());
            }
        }

        const auto renderMethodGroup =
            [&](const std::vector<core::EncodedMethod>& methods, const char* title,
                bool direct) -> Result<void, SmaliError> {
            (void)direct;
            out += "\n# " + std::string(title) + "\n";
            for (const core::EncodedMethod& m : methods) {
                if (m.methodIndex >= dex.methodCount()) {
                    return Err(SmaliError::BadIndex);
                }
                if (Result<void, SmaliError> r =
                        renderMethod(dex, classDefIdx, def, m, out);
                    r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
            return Ok();
        };
        if (Result<void, SmaliError> r =
                renderMethodGroup(cd->directMethods, "direct methods", true);
            r.is_err()) {
            return Err(r.unwrap_err());
        }
        if (Result<void, SmaliError> r =
                renderMethodGroup(cd->virtualMethods, "virtual methods", false);
            r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    return Ok(std::move(out));
}

Result<std::vector<std::pair<std::string, std::string>>, SmaliError> disassembleAll(
    DexFile& dex)
{
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(dex.classCount());
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        Result<std::string, SmaliError> text = disassembleClass(dex, i);
        if (text.is_err()) {
            return Err(text.unwrap_err());
        }
        const Result<std::string, SmaliError> name = typeText(dex, dex.classDefs[i].classIdx);
        if (name.is_err()) {
            return Err(name.unwrap_err());
        }
        std::string file = name.unwrap();
        if (file.size() >= 2 && file.front() == 'L' && file.back() == ';') {
            file = file.substr(1, file.size() - 2);
        }
        out.emplace_back(file + ".smali", std::move(text).unwrap());
    }
    return Ok(std::move(out));
}

}   // namespace dex::smali
