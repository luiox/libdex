/// @file        vacuum.cpp
/// @brief       ID 表引用闭包实现（worklist 不动点）。
#include "dex/core/vacuum.hpp"

#include <map>

#include "dex/core/annotation.hpp"
#include "dex/core/bytes.hpp"
#include "dex/core/builder_edit.hpp"
#include "dex/core/code_item.hpp"
#include "dex/core/debug_info.hpp"
#include "dex/core/encoded_value.hpp"
#include "dex/core/insn.hpp"
#include "dex/core/opcode.hpp"
#include "dex/core/reader.hpp"

namespace dex::core {
namespace {

/// @brief 单张表的 worklist 标记器。
struct Marker
{
    DexFile& dex;
    VacuumKeep& keep;
    std::vector<ca::u32> stringWork;
    std::vector<ca::u32> typeWork;
    std::vector<ca::u32> protoWork;
    std::vector<ca::u32> fieldWork;
    std::vector<ca::u32> methodWork;

    void markString(ca::u32 idx)
    {
        if (idx < keep.strings.size() && !keep.strings[idx]) {
            keep.strings[idx] = true;
            stringWork.push_back(idx);
        }
    }
    void markType(ca::u32 idx)
    {
        if (idx < keep.types.size() && !keep.types[idx]) {
            keep.types[idx] = true;
            typeWork.push_back(idx);
        }
    }
    void markProto(ca::u32 idx);
    void markField(ca::u32 idx)
    {
        if (idx < keep.fields.size() && !keep.fields[idx]) {
            keep.fields[idx] = true;
            fieldWork.push_back(idx);
        }
    }
    void markMethod(ca::u32 idx)
    {
        if (idx < keep.methods.size() && !keep.methods[idx]) {
            keep.methods[idx] = true;
            methodWork.push_back(idx);
        }
    }
    void markValue(const EncodedValue& v);
    void markAnnotation(const EncodedAnnotation& ann);
};

void Marker::markProto(ca::u32 idx)
{
    if (idx >= keep.protos.size() || keep.protos[idx]) {
        return;
    }
    keep.protos[idx] = true;
    protoWork.push_back(idx);
}

void Marker::markAnnotation(const EncodedAnnotation& ann)
{
    markType(ann.typeIdx);
    for (const AnnotationElement& e : ann.elements) {
        markString(e.nameIdx);
        markValue(e.value);
    }
}

void Marker::markValue(const EncodedValue& v)
{
    switch (v.type) {
    case EncodedValueType::String:
        markString(v.index);
        break;
    case EncodedValueType::Type:
        markType(v.index);
        break;
    case EncodedValueType::Field:
    case EncodedValueType::Enum:
        markField(v.index);
        break;
    case EncodedValueType::Method:
        markMethod(v.index);
        break;
    case EncodedValueType::MethodType:
        markProto(v.index);
        break;
    case EncodedValueType::MethodHandle:
        if (v.index < dex.methodHandles.size()) {
            const MethodHandle& h = dex.methodHandles[v.index];
            if (h.handleType <= 3) {
                markField(h.targetIdx);
            } else {
                markMethod(h.targetIdx);
            }
        }
        break;
    case EncodedValueType::Annotation:
        if (v.annotation != nullptr) {
            markAnnotation(*v.annotation);
        }
        break;
    case EncodedValueType::Array:
        for (const EncodedValue& e : v.array) {
            markValue(e);
        }
        break;
    default:
        break;
    }
}

/// @brief 注解项（源偏移）→ 类型 + 元素名 + 值。
Result<void, WriteError> markAnnotationItem(Marker& m, DexFile& dex, ca::u32 off)
{
    if (off == 0) {
        return Ok();
    }
    const Result<const AnnotationItem*, ReadError> item = dex.annotationItem(off);
    if (item.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    m.markAnnotation(item.unwrap()->annotation);
    return Ok();
}

/// @brief annotation_set（源偏移）→ 逐项。
Result<void, WriteError> markAnnotationSet(Marker& m, DexFile& dex, ca::u32 off)
{
    if (off == 0) {
        return Ok();
    }
    const Result<const AnnotationSetItem*, ReadError> set = dex.annotationSet(off);
    if (set.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    for (ca::u32 itemOff : set.unwrap()->annotationOffs) {
        if (Result<void, WriteError> r = markAnnotationItem(m, dex, itemOff);
            r.is_err()) {
            return r;
        }
    }
    return Ok();
}

/// @brief 已编码指令区的引用闭包（源方法体 / 新增方法体 / 代码替换共用）。
Result<void, WriteError> markInsns(Marker& m, const ByteSlice& insns)
{
    const Result<std::vector<Insn>, InsnError> decoded = decodeInsns(insns);
    if (decoded.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    for (const Insn& i : decoded.unwrap()) {
        switch (i.indexKind) {
        case IndexKind::String:
            m.markString(i.index);
            break;
        case IndexKind::Type:
            m.markType(i.index);
            break;
        case IndexKind::Field:
            m.markField(i.index);
            break;
        case IndexKind::Method:
            m.markMethod(i.index);
            break;
        case IndexKind::Proto:
            m.markProto(i.index);
            break;
        case IndexKind::CallSite:
        case IndexKind::MethodHandle:
            // 两表整表保留，目标闭包单独铺开。
            break;
        case IndexKind::None:
        default:
            break;
        }
        if (i.hasProtoIndex) {
            m.markProto(i.protoIndex);
        }
    }
    return Ok();
}

/// @brief debug 信息的字符串/类型引用闭包。
void markDebug(Marker& m, const DebugInfo& info)
{
    for (ca::u32 name : info.parameterNames) {
        if (name != DexFile::kNoIndex) {
            m.markString(name);
        }
    }
    for (const DebugOp& op : info.ops) {
        // 缺席标记是 NO_INDEX（0xFFFFFFFF）而非 0：按 0 哨兵会漏标合法的
        // 索引 0 引用（空串 / 排序最靠前的类型），vacuum 后悄悄换指。
        if (op.nameIdx != DexFile::kNoIndex) {
            m.markString(op.nameIdx);
        }
        if (op.typeIdx != DexFile::kNoIndex) {
            m.markType(op.typeIdx);
        }
        if (op.sigIdx != DexFile::kNoIndex) {
            m.markString(op.sigIdx);
        }
    }
}

/// @brief 方法体 + debug 的闭包（源条目）。
Result<void, WriteError> markCode(Marker& m, DexFile& dex, ca::u32 codeOff)
{
    if (codeOff == 0) {
        return Ok();
    }
    const Result<const CodeItem*, ReadError> code = dex.codeItem(codeOff);
    if (code.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    if (code.unwrap() == nullptr) {
        return Ok();
    }
    const CodeItem* item = code.unwrap();
    if (Result<void, WriteError> r = markInsns(
            m, subOrEmpty(dex.source(), item->insns.offset, item->insns.length));
        r.is_err()) {
        return r;
    }
    // catch handler 的类型索引也是 type_ids 的引用闭包成员；漏标会让仅被
    // .catch 引用的类型被 vacuum 掉，重映射后悄悄落到别的类型上。
    for (const CatchHandler& handler : item->catchHandlers) {
        for (const TypedCatch& typed : handler.typed) {
            m.markType(typed.typeIdx);
        }
    }
    if (item->debugInfoOff != 0) {
        const Result<const DebugInfo*, ReadError> info = dex.debugInfo(item->debugInfoOff);
        if (info.is_err() || info.unwrap() == nullptr) {
            return Err(WriteError::SourceUnreadable);
        }
        markDebug(m, *info.unwrap());
    }
    return Ok();
}

/// @brief 编辑层根：新增字段/方法体、代码替换、自有注解、静态初值覆盖。
Result<void, WriteError> markEditRoots(Marker& m, DexFile& dex,
                                       const MemberEditSet& edits)
{
    for (const auto& entry : edits.fieldsByClass) {
        for (const FieldAddition* add : entry.second) {
            m.markField(add->fieldIdx);
        }
    }
    for (const auto& entry : edits.methodsByClass) {
        for (const MethodAddition* add : entry.second) {
            m.markMethod(add->methodIdx);
            if (!add->insns.empty()) {
                if (Result<void, WriteError> r = markInsns(
                        m, ByteSlice{add->insns.data(), add->insns.size()});
                    r.is_err()) {
                    return r;
                }
            }
            // 新增体的 catch 类型同样是根（与源方法体 markCode 同规则）。
            for (const CatchHandler& handler : add->item.catchHandlers) {
                for (const TypedCatch& typed : handler.typed) {
                    m.markType(typed.typeIdx);
                }
            }
            if (!add->debugInfo.empty()) {
                const Result<DebugInfo, ReadError> info = readDebugInfo(
                    ByteSlice{add->debugInfo.data(), add->debugInfo.size()}, 0);
                if (info.is_err()) {
                    return Err(WriteError::SourceUnreadable);
                }
                markDebug(m, info.unwrap());
            }
        }
    }
    for (const auto& entry : edits.replacements) {
        m.markMethod(entry.first);
        if (!entry.second->insns.empty()) {
            if (Result<void, WriteError> r = markInsns(
                    m, ByteSlice{entry.second->insns.data(), entry.second->insns.size()});
                r.is_err()) {
                return r;
            }
        }
        for (const CatchHandler& handler : entry.second->item.catchHandlers) {
            for (const TypedCatch& typed : handler.typed) {
                m.markType(typed.typeIdx);
            }
        }
    }
    // 自有注解层：池下标 → AnnotationItem。
    const auto markOwned = [&](ca::u32 poolIdx) -> Result<void, WriteError> {
        const AnnotationItem* item = dex.ownedAnnotationItem(poolIdx);
        if (item == nullptr) {
            return Err(WriteError::InvalidModel);
        }
        m.markAnnotation(item->annotation);
        return Ok();
    };
    for (const auto& entry : dex.annotationAttachments()) {
        const AnnotationAttachments& att = entry.second;
        for (ca::u32 idx : att.classItems) {
            if (Result<void, WriteError> r = markOwned(idx); r.is_err()) {
                return r;
            }
        }
        for (const auto& f : att.fields) {
            for (ca::u32 idx : f.second) {
                if (Result<void, WriteError> r = markOwned(idx); r.is_err()) {
                    return r;
                }
            }
        }
        for (const auto& meth : att.methods) {
            for (ca::u32 idx : meth.second) {
                if (Result<void, WriteError> r = markOwned(idx); r.is_err()) {
                    return r;
                }
            }
        }
        for (const auto& meth : att.parameters) {
            for (const std::vector<ca::u32>& pool : meth.second) {
                for (ca::u32 idx : pool) {
                    if (Result<void, WriteError> r = markOwned(idx); r.is_err()) {
                        return r;
                    }
                }
            }
        }
    }
    // 静态初值覆盖。
    for (const auto& entry : dex.staticFieldValueEdits()) {
        for (const auto& v : entry.second) {
            m.markValue(v.second);
        }
    }
    return Ok();
}

}   // namespace


Result<VacuumKeep, WriteError> computeVacuumClosure(DexFile& dex,
                                                    const MemberEditSet* edits)
{
    VacuumKeep keep;
    keep.strings.assign(dex.stringCount(), false);
    keep.types.assign(dex.typeCount(), false);
    keep.protos.assign(dex.protoCount(), false);
    keep.fields.assign(dex.fieldCount(), false);
    keep.methods.assign(dex.methodCount(), false);
    Marker m{dex, keep};

    // method_handles / call_sites 整表保留（数量小、引用点离散）：目标直接铺开。
    for (const MethodHandle& h : dex.methodHandles) {
        if (h.handleType <= 3) {
            m.markField(h.targetIdx);
        } else {
            m.markMethod(h.targetIdx);
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        if (site.callSiteOff == 0) {
            continue;
        }
        const Result<const EncodedArrayItem*, ReadError> arr =
            dex.encodedArray(site.callSiteOff);
        if (arr.is_err() || arr.unwrap() == nullptr) {
            return Err(WriteError::SourceUnreadable);
        }
        for (const EncodedValue& v : arr.unwrap()->values) {
            m.markValue(v);
        }
    }

    // 类定义与成员、注解、静态初值。
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        const ClassDef& def = dex.classDefs[i];
        m.markType(def.classIdx);
        if (def.superclassIdx != DexFile::kNoIndex) {
            m.markType(def.superclassIdx);
        }
        if (def.sourceFileIdx != DexFile::kNoIndex) {
            m.markString(def.sourceFileIdx);
        }
        if (def.interfacesOff != 0 || def.ownedInterfaces) {
            Result<TypeListSpan, ReadError> ifaces = dex.interfaces(i);
            if (ifaces.is_err()) {
                return Err(WriteError::SourceUnreadable);
            }
            const TypeListSpan& span = ifaces.unwrap();
            for (ca::u32 j = 0; j < span.size; ++j) {
                m.markType(span.at(j));
            }
        }

        // class_data：定义成员本身是根；被编辑层移除的成员除外——闭包若
        // 给它们续命，首次 vacuum+removal 的产物会留死条目，二次 vacuum
        // 才掉，破坏「重建即不动点」。
        const Result<const ClassData*, ReadError> data = dex.classData(i);
        if (data.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        if (data.unwrap() != nullptr) {
            for (const EncodedField& f : data.unwrap()->staticFields) {
                if (edits && edits->removedFields.count(f.fieldIndex) != 0) {
                    continue;
                }
                m.markField(f.fieldIndex);
            }
            for (const EncodedField& f : data.unwrap()->instanceFields) {
                if (edits && edits->removedFields.count(f.fieldIndex) != 0) {
                    continue;
                }
                m.markField(f.fieldIndex);
            }
            for (const EncodedMethod& meth : data.unwrap()->directMethods) {
                if (edits && edits->removedMethods.count(meth.methodIndex) != 0) {
                    continue;
                }
                m.markMethod(meth.methodIndex);
            }
            for (const EncodedMethod& meth : data.unwrap()->virtualMethods) {
                if (edits && edits->removedMethods.count(meth.methodIndex) != 0) {
                    continue;
                }
                m.markMethod(meth.methodIndex);
            }
        }

        // 静态初值。
        if (def.staticValuesOff != 0) {
            const Result<const EncodedArrayItem*, ReadError> arr = dex.staticValues(i);
            if (arr.is_err() || arr.unwrap() == nullptr) {
                return Err(WriteError::SourceUnreadable);
            }
            for (const EncodedValue& v : arr.unwrap()->values) {
                m.markValue(v);
            }
        }

        // 注解目录：类/字段/方法/参数四级。
        if (def.annotationsOff != 0) {
            const Result<const AnnotationsDirectory*, ReadError> dir =
                dex.classAnnotations(i);
            if (dir.is_err()) {
                return Err(WriteError::SourceUnreadable);
            }
            if (dir.unwrap() != nullptr) {
                if (Result<void, WriteError> r = markAnnotationSet(
                        m, dex, dir.unwrap()->classAnnotationsOff);
                    r.is_err()) {
                    return Err(r.unwrap_err());
                }
                for (const AnnotationsDirectoryEntry& e : dir.unwrap()->fieldAnnotations) {
                    m.markField(e.memberIdx);
                    if (Result<void, WriteError> r =
                            markAnnotationSet(m, dex, e.annotationsOff);
                        r.is_err()) {
                        return Err(r.unwrap_err());
                    }
                }
                for (const AnnotationsDirectoryEntry& e :
                     dir.unwrap()->methodAnnotations) {
                    m.markMethod(e.memberIdx);
                    if (Result<void, WriteError> r =
                            markAnnotationSet(m, dex, e.annotationsOff);
                        r.is_err()) {
                        return Err(r.unwrap_err());
                    }
                }
                for (const AnnotationsDirectoryEntry& e :
                     dir.unwrap()->parameterAnnotations) {
                    m.markMethod(e.memberIdx);
                    const Result<const AnnotationSetRefList*, ReadError> refs =
                        dex.annotationSetRefList(e.annotationsOff);
                    if (refs.is_err() || refs.unwrap() == nullptr) {
                        return Err(WriteError::SourceUnreadable);
                    }
                    for (ca::u32 setOff : refs.unwrap()->annotationSetOffs) {
                        if (Result<void, WriteError> r =
                                markAnnotationSet(m, dex, setOff);
                            r.is_err()) {
                            return Err(r.unwrap_err());
                        }
                    }
                }
            }
        }
    }

    // 方法体与 debug（含自有编辑层挂上的新方法体：走 BuildOptions 的 method
    // additions 时闭包以编辑层引用为准，这里只铺源条目；新增体引用的表项
    // 在 canonical 重建里恒为已 intern 的新增条目，不受 vacuum 影响）。
    {
        Result<std::map<ca::u32, const ClassData*>, WriteError> collected =
            collectSourceClassData(dex);
        if (collected.is_err()) {
            return Err(collected.unwrap_err());
        }
        for (const auto& entry : collected.unwrap()) {
            const ClassData* data = entry.second;
            if (data == nullptr) {
                continue;
            }
            for (const EncodedMethod& meth : data->directMethods) {
                if (edits && edits->removedMethods.count(meth.methodIndex) != 0) {
                    continue;  // 移除的方法体随之丢弃，不续命其引用
                }
                if (Result<void, WriteError> r = markCode(m, dex, meth.codeOff);
                    r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
            for (const EncodedMethod& meth : data->virtualMethods) {
                if (edits && edits->removedMethods.count(meth.methodIndex) != 0) {
                    continue;
                }
                if (Result<void, WriteError> r = markCode(m, dex, meth.codeOff);
                    r.is_err()) {
                    return Err(r.unwrap_err());
                }
            }
        }
    }

    // 编辑层根（汇编器/增量编辑注入的成员与覆盖）。
    if (edits != nullptr) {
        if (Result<void, WriteError> r = markEditRoots(m, dex, *edits); r.is_err()) {
            return Err(r.unwrap_err());
        }
    }

    // 不动点：method → proto → type → string；field → type → string。
    while (!m.methodWork.empty() || !m.protoWork.empty() || !m.fieldWork.empty() ||
           !m.typeWork.empty()) {
        std::vector<ca::u32> methods = std::move(m.methodWork);
        m.methodWork.clear();
        for (ca::u32 idx : methods) {
            if (idx >= dex.methodIds.size()) {
                return Err(WriteError::InvalidModel);
            }
            const MethodId& id = dex.methodIds[idx];
            m.markType(id.classIdx);
            m.markProto(id.protoIdx);
            m.markString(id.nameIdx);
        }
        std::vector<ca::u32> protos = std::move(m.protoWork);
        m.protoWork.clear();
        for (ca::u32 idx : protos) {
            if (idx >= dex.protoIds.size()) {
                return Err(WriteError::InvalidModel);
            }
            const ProtoId& proto = dex.protoIds[idx];
            m.markString(proto.shortyIdx);
            m.markType(proto.returnTypeIdx);
            if (proto.ownedParameters) {
                const TypeListSpan span = dex.ownedTypeListSpan(proto.ownedParametersIdx);
                for (ca::u32 j = 0; j < span.size; ++j) {
                    m.markType(span.at(j));
                }
            } else if (proto.parametersOff != 0) {
                Result<TypeListSpan, ReadError> list = dex.typeList(proto.parametersOff);
                if (list.is_err()) {
                    return Err(WriteError::SourceUnreadable);
                }
                const TypeListSpan& span = list.unwrap();
                for (ca::u32 j = 0; j < span.size; ++j) {
                    m.markType(span.at(j));
                }
            }
        }
        std::vector<ca::u32> fields = std::move(m.fieldWork);
        m.fieldWork.clear();
        for (ca::u32 idx : fields) {
            if (idx >= dex.fieldIds.size()) {
                return Err(WriteError::InvalidModel);
            }
            const FieldId& id = dex.fieldIds[idx];
            m.markType(id.classIdx);
            m.markType(id.typeIdx);
            m.markString(id.nameIdx);
        }
        std::vector<ca::u32> types = std::move(m.typeWork);
        m.typeWork.clear();
        for (ca::u32 idx : types) {
            if (idx >= dex.typeIds.size()) {
                return Err(WriteError::InvalidModel);
            }
            m.markString(dex.typeIds[idx].descriptorIdx);
        }
    }
    // string 无外延，收尾即可。
    m.stringWork.clear();
    return Ok(std::move(keep));
}

}   // namespace dex::core
