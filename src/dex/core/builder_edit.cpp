/// @file        builder_edit.cpp
/// @brief       编辑应用层实现：成员编辑、静态初值合成与注解合并。
#include "dex/core/builder_edit.hpp"

#include <algorithm>
#include <cstring>
#include <set>

#include "dex/core/annotation.hpp"

namespace dex::core {

namespace {

constexpr ca::u32 kAccPrivate = 0x2u;
constexpr ca::u32 kAccStatic = 0x8u;
constexpr ca::u32 kAccConstructor = 0x10000u;

/// @brief 把 DexFile 的懒解码结果折叠成 builder 错误。
template <typename T>
Result<const T*, WriteError> requireDecoded(Result<const T*, ReadError> result)
{
    if (result.is_err()) {
        return Err(WriteError::SourceUnreadable);
    }
    const T* item = result.unwrap();
    if (item == nullptr) {
        return Err(WriteError::InvalidModel);
    }
    return Ok(item);
}

}   // namespace

bool validIdTables(const DexFile& dex) noexcept
{
    if (dex.stringIds.size() > 0xFFFFFFFFu ||
        dex.typeIds.size() > DexFile::kIdTableLimit ||
        dex.protoIds.size() > DexFile::kIdTableLimit ||
        dex.fieldIds.size() > DexFile::kIdTableLimit ||
        dex.methodIds.size() > DexFile::kIdTableLimit) {
        return false;
    }

    const ca::u32 stringCount = dex.stringCount();
    const ca::u32 typeCount = dex.typeCount();
    const ca::u32 protoCount = dex.protoCount();
    const ca::u32 fieldCount = dex.fieldCount();
    const ca::u32 methodCount = dex.methodCount();

    for (const TypeId& type : dex.typeIds) {
        if (type.descriptorIdx >= stringCount) {
            return false;
        }
    }
    for (const ProtoId& proto : dex.protoIds) {
        if (proto.shortyIdx >= stringCount || proto.returnTypeIdx >= typeCount) {
            return false;
        }
    }
    for (const FieldId& field : dex.fieldIds) {
        if (field.classIdx >= typeCount || field.typeIdx >= typeCount ||
            field.nameIdx >= stringCount) {
            return false;
        }
    }
    for (const MethodId& method : dex.methodIds) {
        if (method.classIdx >= typeCount || method.protoIdx >= protoCount ||
            method.nameIdx >= stringCount) {
            return false;
        }
    }
    for (const ClassDef& def : dex.classDefs) {
        if (def.classIdx >= typeCount ||
            (def.superclassIdx != DexFile::kNoIndex && def.superclassIdx >= typeCount) ||
            (def.sourceFileIdx != DexFile::kNoIndex && def.sourceFileIdx >= stringCount)) {
            return false;
        }
    }
    for (const CallSiteId& site : dex.callSites) {
        if (site.callSiteOff == 0) {
            return false;
        }
    }
    for (const MethodHandle& handle : dex.methodHandles) {
        if (handle.handleType > 8) {
            return false;
        }
        const ca::u32 limit = handle.handleType <= 3 ? fieldCount : methodCount;
        if (handle.targetIdx >= limit) {
            return false;
        }
    }
    return true;
}

Result<std::map<ca::u32, const ClassData*>, WriteError> collectSourceClassData(DexFile& dex)
{
    std::map<ca::u32, const ClassData*> classDataByOff;
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        const ca::u32 off = dex.classDefs[i].classDataOff;
        if (off == 0 || classDataByOff.count(off) != 0) {
            continue;
        }
        const Result<const ClassData*, WriteError> data = requireDecoded(dex.classData(i));
        if (data.is_err()) {
            return Err(data.unwrap_err());
        }
        classDataByOff.emplace(off, data.unwrap());
    }
    return Ok(std::move(classDataByOff));
}

Result<MemberEditSet, WriteError> collectMemberEdits(
    const DexFile& dex, const BuildOptions& options,
    const std::map<ca::u32, const ClassData*>& classDataByOff)
{
    MemberEditSet edits;

    for (const CodeReplacement& repl : options.codeReplacements) {
        if (repl.methodIdx >= dex.methodCount()) {
            return Err(WriteError::InvalidModel);
        }
        if (!edits.replacements.emplace(repl.methodIdx, &repl).second) {
            return Err(WriteError::InvalidModel);
        }
        if (repl.insns.size() != static_cast<ca::usize>(repl.item.insnsSize) * 2u) {
            return Err(WriteError::Unencodable);
        }
    }

    for (ca::u32 fieldIdx : options.removedFields) {
        if (fieldIdx >= dex.fieldCount()) {
            return Err(WriteError::InvalidModel);
        }
        edits.removedFields.insert(fieldIdx);
    }
    for (ca::u32 methodIdx : options.removedMethods) {
        if (methodIdx >= dex.methodCount() ||
            edits.replacements.count(methodIdx) != 0) {
            return Err(WriteError::InvalidModel);
        }
        edits.removedMethods.insert(methodIdx);
    }

    for (const auto& entry : classDataByOff) {
        const ClassData& data = *entry.second;
        const std::vector<EncodedField>* fieldLists[2] = {&data.staticFields,
                                                          &data.instanceFields};
        for (const std::vector<EncodedField>* fields : fieldLists) {
            for (const EncodedField& field : *fields) {
                if (field.fieldIndex >= dex.fieldCount()) {
                    return Err(WriteError::InvalidModel);
                }
                edits.definedFields.insert(field.fieldIndex);
            }
        }
        const std::vector<EncodedMethod>* lists[2] = {&data.directMethods,
                                                      &data.virtualMethods};
        for (const std::vector<EncodedMethod>* list : lists) {
            for (const EncodedMethod& method : *list) {
                if (method.methodIndex >= dex.methodCount()) {
                    return Err(WriteError::InvalidModel);
                }
                edits.definedMethods.insert(method.methodIndex);
                if (method.codeOff == 0) {
                    continue;
                }
                if (!edits.methodsWithCode.insert(method.methodIndex).second) {
                    return Err(WriteError::InvalidModel);  // 同一方法被两处定义
                }
            }
        }
    }
    for (const auto& entry : edits.replacements) {
        if (edits.methodsWithCode.count(entry.first) == 0) {
            return Err(WriteError::InvalidModel);
        }
    }

    std::unordered_set<ca::u32> addedFields;
    std::unordered_set<ca::u32> addedMethods;
    for (const FieldAddition& add : options.fieldAdditions) {
        if (add.classDefIdx >= dex.classCount() || add.fieldIdx >= dex.fieldCount()) {
            return Err(WriteError::InvalidModel);
        }
        // static/instance 分组由 isStatic 决定，写入的标志位必须一致。
        if (add.isStatic != ((add.accessFlags & kAccStatic) != 0)) {
            return Err(WriteError::InvalidModel);
        }
        if (edits.definedFields.count(add.fieldIdx) != 0 ||
            edits.removedFields.count(add.fieldIdx) != 0 ||
            !addedFields.insert(add.fieldIdx).second) {
            return Err(WriteError::InvalidModel);  // 重复定义或与删除冲突
        }
        edits.fieldsByClass[add.classDefIdx].push_back(&add);
    }
    for (const MethodAddition& add : options.methodAdditions) {
        if (add.classDefIdx >= dex.classCount() || add.methodIdx >= dex.methodCount()) {
            return Err(WriteError::InvalidModel);
        }
        if (edits.definedMethods.count(add.methodIdx) != 0 ||
            !addedMethods.insert(add.methodIdx).second ||
            edits.replacements.count(add.methodIdx) != 0 ||
            edits.removedMethods.count(add.methodIdx) != 0) {
            return Err(WriteError::InvalidModel);  // 重复定义或与替换/删除冲突
        }
        if (add.insns.size() != static_cast<ca::usize>(add.item.insnsSize) * 2u) {
            return Err(WriteError::Unencodable);
        }
        edits.methodsByClass[add.classDefIdx].push_back(&add);
    }

    for (const AccessFlagEdit& edit : options.fieldAccessFlags) {
        if (edit.index >= dex.fieldCount() || edits.removedFields.count(edit.index) != 0 ||
            addedFields.count(edit.index) != 0 ||
            edits.definedFields.count(edit.index) == 0 ||
            !edits.fieldFlagEdits.emplace(edit.index, edit.accessFlags).second) {
            return Err(WriteError::InvalidModel);
        }
    }
    for (const AccessFlagEdit& edit : options.methodAccessFlags) {
        if (edit.index >= dex.methodCount() || edits.removedMethods.count(edit.index) != 0 ||
            addedMethods.count(edit.index) != 0 ||
            edits.definedMethods.count(edit.index) == 0 ||
            !edits.methodFlagEdits.emplace(edit.index, edit.accessFlags).second) {
            return Err(WriteError::InvalidModel);
        }
    }

    const auto ensureEdit = [&](ca::u32 classDefIdx) -> ClassData& {
        ClassData& edit = edits.classDataEdits[classDefIdx];
        if (edit.raw.length == 0 && edit.staticFields.empty() &&
            edit.instanceFields.empty() && edit.directMethods.empty() &&
            edit.virtualMethods.empty()) {
            const ca::u32 off = dex.classDefs[classDefIdx].classDataOff;
            if (off != 0) {
                const auto found = classDataByOff.find(off);
                if (found != classDataByOff.end()) {
                    edit = *found->second;
                }
            }
        }
        return edit;
    };
    for (const auto& entry : edits.fieldsByClass) {
        ClassData& edit = ensureEdit(entry.first);
        for (const FieldAddition* add : entry.second) {
            EncodedField field;
            field.fieldIndex = add->fieldIdx;
            field.accessFlags = add->accessFlags;
            (add->isStatic ? edit.staticFields : edit.instanceFields).push_back(field);
        }
    }
    for (const auto& entry : edits.methodsByClass) {
        ClassData& edit = ensureEdit(entry.first);
        for (const MethodAddition* add : entry.second) {
            EncodedMethod method;
            method.methodIndex = add->methodIdx;
            method.accessFlags = add->accessFlags;
            method.codeOff = 1;  // 占位，布局后替换为真实 code_off
            const bool direct = (add->accessFlags &
                                 (kAccPrivate | kAccStatic | kAccConstructor)) != 0;
            (direct ? edit.directMethods : edit.virtualMethods).push_back(method);
        }
    }
    return Ok(std::move(edits));
}

Result<void, WriteError> applyMemberEdits(ClassData& data, const MemberEditSet& edits)
{
    const auto fieldRemoved = [&edits](const EncodedField& field) {
        return edits.removedFields.count(field.fieldIndex) != 0;
    };
    for (std::vector<EncodedField>* list : {&data.staticFields, &data.instanceFields}) {
        list->erase(std::remove_if(list->begin(), list->end(), fieldRemoved), list->end());
    }
    const auto methodRemoved = [&edits](const EncodedMethod& method) {
        return edits.removedMethods.count(method.methodIndex) != 0;
    };
    for (std::vector<EncodedMethod>* list : {&data.directMethods, &data.virtualMethods}) {
        list->erase(std::remove_if(list->begin(), list->end(), methodRemoved), list->end());
    }

    if (!edits.fieldFlagEdits.empty()) {
        for (std::vector<EncodedField>* list : {&data.staticFields, &data.instanceFields}) {
            for (EncodedField& field : *list) {
                const auto edit = edits.fieldFlagEdits.find(field.fieldIndex);
                if (edit == edits.fieldFlagEdits.end()) {
                    continue;
                }
                if (((field.accessFlags ^ edit->second) & kAccStatic) != 0) {
                    return Err(WriteError::InvalidModel);  // 不能改 static 位
                }
                field.accessFlags = edit->second;
            }
        }
    }
    if (!edits.methodFlagEdits.empty()) {
        std::vector<EncodedMethod> moved;
        for (std::vector<EncodedMethod>* list : {&data.directMethods,
                                                 &data.virtualMethods}) {
            for (auto it = list->begin(); it != list->end();) {
                const auto edit = edits.methodFlagEdits.find(it->methodIndex);
                if (edit == edits.methodFlagEdits.end()) {
                    ++it;
                    continue;
                }
                EncodedMethod method = *it;
                method.accessFlags = edit->second;
                moved.push_back(std::move(method));
                it = list->erase(it);
            }
        }
        for (EncodedMethod& method : moved) {
            const bool direct =
                (method.accessFlags & (kAccPrivate | kAccStatic | kAccConstructor)) != 0;
            (direct ? data.directMethods : data.virtualMethods).push_back(std::move(method));
        }
    }
    return Ok();
}

Result<std::optional<EncodedArrayItem>, WriteError> synthesizeStaticValues(
    DexFile& dex, ca::u32 classDefIdx, const ClassData* original,
    const std::vector<ca::u32>& addedStatic, const MemberEditSet& edits,
    const std::vector<ca::u32>* fieldRemap)
{
    const std::map<ca::u32, EncodedValue>* valueEdits = nullptr;
    const auto& allEdits = dex.staticFieldValueEdits();
    const auto editBucket = allEdits.find(classDefIdx);
    if (editBucket != allEdits.end()) {
        valueEdits = &editBucket->second;
    }

    bool changed = !addedStatic.empty() || valueEdits != nullptr;
    if (!changed && original != nullptr) {
        for (const EncodedField& field : original->staticFields) {
            if (edits.removedFields.count(field.fieldIndex) != 0) {
                changed = true;
                break;
            }
        }
    }
    if (!changed) {
        return Ok(std::optional<EncodedArrayItem>{});
    }

    const auto defaultStaticValue = [&](ca::u32 fieldIdx)
        -> Result<EncodedValue, WriteError> {
        Result<jstr::MUtf8StringRef, ReadError> descriptor = dex.fieldTypeDescriptor(fieldIdx);
        if (descriptor.is_err()) {
            return Err(WriteError::SourceUnreadable);
        }
        const std::string_view text = descriptor.unwrap().as_std_view();
        if (text.empty()) {
            return Err(WriteError::InvalidModel);
        }
        EncodedValue value;
        switch (text[0]) {
            case 'Z': value.type = EncodedValueType::Boolean; break;
            case 'B': value.type = EncodedValueType::Byte; break;
            case 'S': value.type = EncodedValueType::Short; break;
            case 'C': value.type = EncodedValueType::Char; break;
            case 'I': value.type = EncodedValueType::Int; break;
            case 'J': value.type = EncodedValueType::Long; break;
            case 'F': value.type = EncodedValueType::Float; break;
            case 'D': value.type = EncodedValueType::Double; break;
            case 'L':
            case '[': value.type = EncodedValueType::Null; break;
            default: return Err(WriteError::InvalidModel);
        }
        value.valueArg = 0;
        return Ok(std::move(value));
    };

    const ca::u32 valuesOff = dex.classDefs[classDefIdx].staticValuesOff;
    EncodedArrayItem synthesizedEmpty;
    const EncodedArrayItem* arrayPtr = &synthesizedEmpty;
    if (valuesOff != 0) {
        const Result<const EncodedArrayItem*, WriteError> fetched =
            requireDecoded(dex.encodedArray(valuesOff));
        if (fetched.is_err()) {
            return Err(fetched.unwrap_err());
        }
        arrayPtr = fetched.unwrap();
    }
    const EncodedArrayItem& array = *arrayPtr;
    const ca::usize originalCount = original == nullptr ? 0 : original->staticFields.size();
    // 规范允许省略尾部的默认值槽位；数组比静态字段还长才是模型不自洽。
    if (array.values.size() > originalCount) {
        return Err(WriteError::InvalidModel);
    }

    struct StaticSlot
    {
        ca::u32 fieldIdx = 0;
        bool fromOriginal = false;
        ca::usize valuePos = 0;
    };
    const auto slotKey = [&](ca::u32 fieldIdx) {
        return fieldRemap == nullptr ? fieldIdx : (*fieldRemap)[fieldIdx];
    };
    std::vector<StaticSlot> slots;
    ca::usize pos = 0;
    if (original != nullptr) {
        for (const EncodedField& field : original->staticFields) {
            const ca::usize valuePos = pos++;
            if (edits.removedFields.count(field.fieldIndex) == 0) {
                slots.push_back(StaticSlot{field.fieldIndex, true, valuePos});
            }
        }
    }
    for (ca::u32 fieldIdx : addedStatic) {
        slots.push_back(StaticSlot{fieldIdx, false, 0});
    }
    std::sort(slots.begin(), slots.end(),
              [&slotKey](const StaticSlot& a, const StaticSlot& b) {
                  return slotKey(a.fieldIdx) < slotKey(b.fieldIdx);
              });

    // 编辑目标必须落在最终静态字段集合里（实例字段、删除字段、未定义字段都拒绝）。
    if (valueEdits != nullptr) {
        for (const auto& entry : *valueEdits) {
            bool found = false;
            for (const StaticSlot& slot : slots) {
                if (slot.fieldIdx == entry.first) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return Err(WriteError::InvalidModel);
            }
        }
    }

    EncodedArrayItem synthesized;
    synthesized.values.reserve(slots.size());
    for (const StaticSlot& slot : slots) {
        if (valueEdits != nullptr) {
            const auto edited = valueEdits->find(slot.fieldIdx);
            if (edited != valueEdits->end()) {
                synthesized.values.push_back(edited->second);
                continue;
            }
        }
        if (slot.fromOriginal && slot.valuePos < array.values.size()) {
            synthesized.values.push_back(array.values[slot.valuePos]);
            continue;
        }
        // 新增字段与被省略的尾部槽位都填类型默认值。
        Result<EncodedValue, WriteError> value = defaultStaticValue(slot.fieldIdx);
        if (value.is_err()) {
            return Err(value.unwrap_err());
        }
        synthesized.values.push_back(value.unwrap());
    }
    return Ok(std::optional<EncodedArrayItem>(std::move(synthesized)));
}

namespace {

/// @brief 覆盖目标必须在生效 class_data（含注入成员，扣除删除）中有定义。
Result<void, WriteError> validateAnnotationTargets(const AnnotationAttachments& attach,
                                                   ca::u32 classDefIdx,
                                                   DexFile& dex,
                                                   const MemberEditSet& memberEdits,
                                                   const std::map<ca::u32,
                                                                  const ClassData*>&
                                                       classDataByOff)
{
    const ClassData* effective = nullptr;
    const auto edited = memberEdits.classDataEdits.find(classDefIdx);
    if (edited != memberEdits.classDataEdits.end()) {
        effective = &edited->second;
    } else {
        const ca::u32 off = dex.classDefs[classDefIdx].classDataOff;
        if (off != 0) {
            const auto found = classDataByOff.find(off);
            if (found == classDataByOff.end()) {
                return Err(WriteError::InvalidModel);
            }
            effective = found->second;
        }
    }
    const auto memberDefined = [&effective, &memberEdits](bool method, ca::u32 memberIdx) {
        if (method ? memberEdits.removedMethods.count(memberIdx) != 0
                   : memberEdits.removedFields.count(memberIdx) != 0) {
            return false;  // 成员已被删除，不能作为注解目标
        }
        if (effective == nullptr) {
            return false;
        }
        if (method) {
            for (const EncodedMethod& m : effective->directMethods) {
                if (m.methodIndex == memberIdx) return true;
            }
            for (const EncodedMethod& m : effective->virtualMethods) {
                if (m.methodIndex == memberIdx) return true;
            }
            return false;
        }
        for (const EncodedField& f : effective->staticFields) {
            if (f.fieldIndex == memberIdx) return true;
        }
        for (const EncodedField& f : effective->instanceFields) {
            if (f.fieldIndex == memberIdx) return true;
        }
        return false;
    };
    for (const auto& entry : attach.fields) {
        if (!memberDefined(false, entry.first)) {
            return Err(WriteError::InvalidModel);
        }
    }
    for (const auto& entry : attach.methods) {
        if (!memberDefined(true, entry.first)) {
            return Err(WriteError::InvalidModel);
        }
    }
    for (const auto& entry : attach.parameters) {
        if (!memberDefined(true, entry.first)) {
            return Err(WriteError::InvalidModel);
        }
        const Result<TypeListSpan, ReadError> params =
            dex.protoParameters(dex.methodIds[entry.first].protoIdx);
        if (params.is_err() || params.unwrap().size != entry.second.size()) {
            return Err(WriteError::InvalidModel);  // 参数个数不匹配
        }
    }
    return Ok();
}

}   // namespace

Result<AnnotationPlan, WriteError> planAnnotations(DexFile& dex,
                                                   const BuildOptions& options,
                                                   const MemberEditSet& memberEdits,
                                                   const std::map<ca::u32,
                                                                  const ClassData*>&
                                                       classDataByOff)
{
    AnnotationPlan plan;

    const std::map<ca::u32, AnnotationAttachments>& attachments = dex.annotationAttachments();
    if (!attachments.empty() && options.stripAnnotations) {
        return Err(WriteError::InvalidModel);  // 剥离与新建注解互相矛盾
    }
    for (const auto& entry : attachments) {
        if (entry.first >= dex.classCount()) {
            return Err(WriteError::InvalidModel);
        }
        const Result<void, WriteError> targets =
            validateAnnotationTargets(entry.second, entry.first, dex, memberEdits,
                                      classDataByOff);
        if (targets.is_err()) {
            return Err(targets.unwrap_err());
        }
    }

    std::set<ca::u32> directoryOffs;
    if (!options.stripAnnotations) {
        for (const ClassDef& def : dex.classDefs) {
            if (def.annotationsOff != 0) {
                directoryOffs.insert(def.annotationsOff);
            }
        }
    }
    for (ca::u32 off : directoryOffs) {
        const Result<const AnnotationsDirectory*, WriteError> directory =
            requireDecoded(dex.annotationsDirectory(off));
        if (directory.is_err()) {
            return Err(directory.unwrap_err());
        }
        plan.directories.emplace(off, directory.unwrap());
    }

    plan.dirs.resize(dex.classCount());
    ca::u32 ownedSetKeySeq = 0;
    ca::u32 ownedRefListKeySeq = 0;
    for (ca::u32 i = 0; i < dex.classCount(); ++i) {
        const ClassDef& def = dex.classDefs[i];
        const AnnotationsDirectory* source = nullptr;
        if (def.annotationsOff != 0) {
            // strip 下 plan.directories 为空；任何 find 落空都必须走
            // end() 分支，解引用 end() 读到的是容器节点的堆填充值。
            const auto found = plan.directories.find(def.annotationsOff);
            if (found != plan.directories.end()) {
                source = found->second;
            }
        }
        const AnnotationAttachments* attach = nullptr;
        const auto found = attachments.find(i);
        if (found != attachments.end()) {
            attach = &found->second;
        }
        EffectiveDirectory& eff = plan.dirs[i];
        eff.overridden = attach != nullptr;

        if (attach != nullptr && attach->hasClass) {
            if (!attach->classItems.empty()) {
                const ca::u32 key = kOwnedSetKeyBase + ownedSetKeySeq++;
                eff.content.classAnnotationsOff = key;
                plan.ownedSetItems.emplace(key, &attach->classItems);
            }
        } else if (source != nullptr) {
            eff.content.classAnnotationsOff = source->classAnnotationsOff;
        }

        const auto mergeEntries = [&](const std::vector<AnnotationsDirectoryEntry>& src,
                                      const std::map<ca::u32, std::vector<ca::u32>>* overrides,
                                      std::vector<AnnotationsDirectoryEntry>& out) {
            if (src.empty() && overrides == nullptr) {
                return;
            }
            for (const AnnotationsDirectoryEntry& entry : src) {
                if (overrides != nullptr && overrides->count(entry.memberIdx) != 0) {
                    continue;  // 该成员被覆盖，源条目不进入生效目录
                }
                out.push_back(entry);
            }
            if (overrides == nullptr) {
                return;
            }
            for (const auto& entry : *overrides) {
                if (entry.second.empty()) {
                    continue;  // 显式清空：无条目
                }
                const ca::u32 key = kOwnedSetKeyBase + ownedSetKeySeq++;
                out.push_back(AnnotationsDirectoryEntry{entry.first, key});
                plan.ownedSetItems.emplace(key, &entry.second);
            }
        };
        const std::vector<AnnotationsDirectoryEntry> noEntries;
        mergeEntries(source == nullptr ? noEntries : source->fieldAnnotations,
                     attach == nullptr ? nullptr : &attach->fields,
                     eff.content.fieldAnnotations);
        mergeEntries(source == nullptr ? noEntries : source->methodAnnotations,
                     attach == nullptr ? nullptr : &attach->methods,
                     eff.content.methodAnnotations);

        for (const AnnotationsDirectoryEntry& entry :
             source == nullptr ? noEntries : source->parameterAnnotations) {
            const bool overridden =
                attach != nullptr && attach->parameters.count(entry.memberIdx) != 0;
            if (!overridden) {
                eff.content.parameterAnnotations.push_back(entry);
            }
        }
        if (attach != nullptr) {
            for (const auto& entry : attach->parameters) {
                std::vector<ca::u32> setKeys;
                setKeys.reserve(entry.second.size());
                for (const std::vector<ca::u32>& items : entry.second) {
                    if (items.empty()) {
                        setKeys.push_back(0);
                        continue;
                    }
                    const ca::u32 key = kOwnedSetKeyBase + ownedSetKeySeq++;
                    setKeys.push_back(key);
                    plan.ownedSetItems.emplace(key, &items);
                }
                const ca::u32 refListKey = kOwnedRefListKeyBase + ownedRefListKeySeq++;
                eff.content.parameterAnnotations.push_back(
                    AnnotationsDirectoryEntry{entry.first, refListKey});
                plan.ownedRefListSets.emplace(refListKey, std::move(setKeys));
            }
        }

        eff.effectivelyEmpty = eff.content.classAnnotationsOff == 0 &&
                               eff.content.fieldAnnotations.empty() &&
                               eff.content.methodAnnotations.empty() &&
                               eff.content.parameterAnnotations.empty();
    }
    return Ok(std::move(plan));
}

}   // namespace dex::core
