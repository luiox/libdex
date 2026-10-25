/// @file        annotation_write_test.cpp
/// @brief       可写注解层：类/字段/方法/参数注解的新建、替换、清空与拒绝面。
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

using namespace dex::core;

namespace {

std::unique_ptr<DexFile> readFixture()
{
    const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
    auto parsed = readDex(dex_test::asSlice(bytes));
    if (parsed.is_err()) {
        return nullptr;
    }
    return std::move(parsed).unwrap();
}

/// 构造一个 @Ltest/Xxx;(value="x") 风格的注解项并入池。
ca::u32 internAuthorAnnotation(DexFile& file, const char* typeName)
{
    const auto typeIdx = file.addType(typeName);
    if (typeIdx.is_err()) {
        return DexFile::kNoIndex;
    }
    const auto valueName = file.internUtf8("value");
    if (valueName.is_err()) {
        return DexFile::kNoIndex;
    }
    const auto text = file.internUtf8("x");
    if (text.is_err()) {
        return DexFile::kNoIndex;
    }
    AnnotationItem item;
    item.visibility = static_cast<ca::u8>(AnnotationVisibility::Runtime);
    item.annotation.typeIdx = typeIdx.unwrap();
    AnnotationElement element;
    element.nameIdx = valueName.unwrap();
    element.value.type = EncodedValueType::String;
    element.value.index = text.unwrap();
    item.annotation.elements.push_back(element);
    const auto handle = file.addAnnotationItem(item);
    return handle.is_ok() ? handle.unwrap() : DexFile::kNoIndex;
}

/// 在模型里找方法索引；找不到返回 kNoIndex（string 是懒解码入口，需可变引用）。
ca::u32 findMethodByName(DexFile& file, const char* name)
{
    for (ca::u32 i = 0; i < file.methodCount(); ++i) {
        const auto method = file.string(file.methodIds[i].nameIdx);
        if (method.is_ok() && method.unwrap().as_std_view() == name) {
            return i;
        }
    }
    return DexFile::kNoIndex;
}

}   // namespace

TEST(DexAnnotationWrite, AddsClassFieldAndMethodAnnotations)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/Author;");
    ASSERT_NE(handle, DexFile::kNoIndex);

    // 同一注解项挂到类、字段与方法：三个 set 引用同一个 item。
    ASSERT_TRUE(file->setClassAnnotations(0, {handle}).is_ok());
    ASSERT_TRUE(file->setFieldAnnotations(0, 0, {handle}).is_ok());
    const ca::u32 foo = findMethodByName(*file, "foo");
    ASSERT_NE(foo, DexFile::kNoIndex);
    ASSERT_TRUE(file->setMethodAnnotations(0, foo, {handle}).is_ok());

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    ASSERT_NE(second->classDefs[0].annotationsOff, 0u);
    const auto directory = second->annotationsDirectory(second->classDefs[0].annotationsOff);
    ASSERT_TRUE(directory.is_ok());
    const AnnotationsDirectory* dir = directory.unwrap();
    ASSERT_NE(dir->classAnnotationsOff, 0u);
    ASSERT_EQ(dir->fieldAnnotations.size(), 1u);
    ASSERT_EQ(dir->methodAnnotations.size(), 1u);
    ASSERT_TRUE(dir->parameterAnnotations.empty());

    std::vector<ca::u32> itemOffs;
    for (ca::u32 setOff : {dir->classAnnotationsOff,
                           dir->fieldAnnotations[0].annotationsOff,
                           dir->methodAnnotations[0].annotationsOff}) {
        const auto set = second->annotationSet(setOff);
        ASSERT_TRUE(set.is_ok());
        ASSERT_EQ(set.unwrap()->annotationOffs.size(), 1u);
        const auto item = second->annotationItem(set.unwrap()->annotationOffs[0]);
        ASSERT_TRUE(item.is_ok());
        EXPECT_EQ(item.unwrap()->visibility, static_cast<ca::u8>(AnnotationVisibility::Runtime));
        const auto descriptor = second->typeDescriptor(item.unwrap()->annotation.typeIdx);
        ASSERT_TRUE(descriptor.is_ok());
        EXPECT_EQ(descriptor.unwrap().as_std_view(), "Ltest/Author;");
        ASSERT_EQ(item.unwrap()->annotation.elements.size(), 1u);
        const auto elementName = second->string(item.unwrap()->annotation.elements[0].nameIdx);
        ASSERT_TRUE(elementName.is_ok());
        EXPECT_EQ(elementName.unwrap().as_std_view(), "value");
        const auto elementText = second->string(item.unwrap()->annotation.elements[0].value.index);
        ASSERT_TRUE(elementText.is_ok());
        EXPECT_EQ(elementText.unwrap().as_std_view(), "x");
        itemOffs.push_back(set.unwrap()->annotationOffs[0]);
    }
    // 同一池下标只发射一个 item：三个 set 指向同一偏移。
    EXPECT_EQ(itemOffs[0], itemOffs[1]);
    EXPECT_EQ(itemOffs[1], itemOffs[2]);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexAnnotationWrite, ReplacesAndClearsAnnotations)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const ca::u32 first = internAuthorAnnotation(*file, "Ltest/First;");
    const ca::u32 foo = findMethodByName(*file, "foo");
    ASSERT_NE(first, DexFile::kNoIndex);
    ASSERT_NE(foo, DexFile::kNoIndex);
    ASSERT_TRUE(file->setClassAnnotations(0, {first}).is_ok());
    ASSERT_TRUE(file->setMethodAnnotations(0, foo, {first}).is_ok());

    BuildOptions options;
    options.keepUnknownSections = false;
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    // 第二轮：类注解换成 Second，方法注解清空。
    const ca::u32 replacement = internAuthorAnnotation(*second, "Ltest/Second;");
    ASSERT_NE(replacement, DexFile::kNoIndex);
    const ca::u32 fooAgain = findMethodByName(*second, "foo");
    ASSERT_NE(fooAgain, DexFile::kNoIndex);
    ASSERT_TRUE(second->setClassAnnotations(0, {replacement}).is_ok());
    ASSERT_TRUE(second->setMethodAnnotations(0, fooAgain, {}).is_ok());

    auto rebuilt2 = buildDex(*second, options);
    ASSERT_TRUE(rebuilt2.is_ok()) << to_string(rebuilt2.unwrap_err());
    auto third = readDex(dex_test::asSlice(rebuilt2.unwrap()));
    ASSERT_TRUE(third.is_ok());
    std::unique_ptr<DexFile> parsed3 = std::move(third).unwrap();

    const auto directory = parsed3->annotationsDirectory(parsed3->classDefs[0].annotationsOff);
    ASSERT_TRUE(directory.is_ok());
    const AnnotationsDirectory* dir = directory.unwrap();
    ASSERT_NE(dir->classAnnotationsOff, 0u);
    EXPECT_TRUE(dir->methodAnnotations.empty());  // 方法条目被清空
    const auto set = parsed3->annotationSet(dir->classAnnotationsOff);
    ASSERT_TRUE(set.is_ok());
    ASSERT_EQ(set.unwrap()->annotationOffs.size(), 1u);
    const auto item = parsed3->annotationItem(set.unwrap()->annotationOffs[0]);
    ASSERT_TRUE(item.is_ok());
    const auto descriptor = parsed3->typeDescriptor(item.unwrap()->annotation.typeIdx);
    ASSERT_TRUE(descriptor.is_ok());
    EXPECT_EQ(descriptor.unwrap().as_std_view(), "Ltest/Second;");

    auto again = buildDex(*parsed3, options);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt2.unwrap());
}

TEST(DexAnnotationWrite, AddsParameterAnnotationsForNewMethod)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);

    // 新方法 run(II)V：注入方法体并给第一个参数挂注解。
    const auto protoIdx = file->addProtoWithParams(3 /* V */, {0 /* I */, 0 /* I */});
    ASSERT_TRUE(protoIdx.is_ok());
    const auto name = file->internUtf8("run");
    ASSERT_TRUE(name.is_ok());
    const auto methodIdx = file->addMethod(1, protoIdx.unwrap(), name.unwrap());
    ASSERT_TRUE(methodIdx.is_ok());

    MethodAddition addition;
    addition.classDefIdx = 0;
    addition.methodIdx = methodIdx.unwrap();
    addition.accessFlags = 0x1;
    addition.item.insnsSize = 1;
    addition.insns = {0x0e, 0x00};

    const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/Param;");
    ASSERT_NE(handle, DexFile::kNoIndex);
    ASSERT_TRUE(file->setParameterAnnotations(0, methodIdx.unwrap(), {{handle}, {}}).is_ok());

    BuildOptions options;
    options.keepUnknownSections = false;
    options.methodAdditions.push_back(addition);
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> rebuilt = std::move(built).unwrap();

    auto reparsed = readDex(dex_test::asSlice(rebuilt));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();

    const auto directory = second->annotationsDirectory(second->classDefs[0].annotationsOff);
    ASSERT_TRUE(directory.is_ok());
    const AnnotationsDirectory* dir = directory.unwrap();
    ASSERT_EQ(dir->parameterAnnotations.size(), 1u);
    const ca::u32 runIdx = findMethodByName(*second, "run");
    ASSERT_NE(runIdx, DexFile::kNoIndex);
    EXPECT_EQ(dir->parameterAnnotations[0].memberIdx, runIdx);

    const auto refList =
        second->annotationSetRefList(dir->parameterAnnotations[0].annotationsOff);
    ASSERT_TRUE(refList.is_ok());
    ASSERT_EQ(refList.unwrap()->annotationSetOffs.size(), 2u);
    const auto firstSet = second->annotationSet(refList.unwrap()->annotationSetOffs[0]);
    ASSERT_TRUE(firstSet.is_ok());
    ASSERT_EQ(firstSet.unwrap()->annotationOffs.size(), 1u);
    // 无注解的参数槽位写 0，与 d8 的空参数表示一致。
    EXPECT_EQ(refList.unwrap()->annotationSetOffs[1], 0u);

    BuildOptions plain;
    plain.keepUnknownSections = false;
    auto again = buildDex(*second, plain);
    ASSERT_TRUE(again.is_ok()) << to_string(again.unwrap_err());
    EXPECT_EQ(again.unwrap(), rebuilt);
}

TEST(DexAnnotationWrite, AnnotatesInjectedField)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const auto name = file->internUtf8("gen");
    ASSERT_TRUE(name.is_ok());
    const auto fieldIdx = file->addField(1, 0, name.unwrap());
    ASSERT_TRUE(fieldIdx.is_ok());

    FieldAddition addition;
    addition.classDefIdx = 0;
    addition.fieldIdx = fieldIdx.unwrap();
    addition.accessFlags = 0x9;
    addition.isStatic = true;

    const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/Field;");
    ASSERT_NE(handle, DexFile::kNoIndex);
    ASSERT_TRUE(file->setFieldAnnotations(0, fieldIdx.unwrap(), {handle}).is_ok());

    BuildOptions options;
    options.keepUnknownSections = false;
    options.fieldAdditions.push_back(addition);
    auto built = buildDex(*file, options);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());

    auto reparsed = readDex(dex_test::asSlice(built.unwrap()));
    ASSERT_TRUE(reparsed.is_ok());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    const auto directory = second->annotationsDirectory(second->classDefs[0].annotationsOff);
    ASSERT_TRUE(directory.is_ok());
    ASSERT_EQ(directory.unwrap()->fieldAnnotations.size(), 1u);
    const auto set =
        second->annotationSet(directory.unwrap()->fieldAnnotations[0].annotationsOff);
    ASSERT_TRUE(set.is_ok());
    ASSERT_EQ(set.unwrap()->annotationOffs.size(), 1u);
}

TEST(DexAnnotationWrite, RejectsInvalidAnnotationEdits)
{
    // 剥离与新建注解矛盾。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/A;");
        ASSERT_NE(handle, DexFile::kNoIndex);
        ASSERT_TRUE(file->setClassAnnotations(0, {handle}).is_ok());
        BuildOptions options;
        options.keepUnknownSections = false;
        options.stripAnnotations = true;
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 注解目标未在类中定义（只在 ID 表里加了字段）。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const auto name = file->internUtf8("ghost");
        ASSERT_TRUE(name.is_ok());
        const auto fieldIdx = file->addField(1, 0, name.unwrap());
        ASSERT_TRUE(fieldIdx.is_ok());
        const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/A;");
        ASSERT_NE(handle, DexFile::kNoIndex);
        ASSERT_TRUE(file->setFieldAnnotations(0, fieldIdx.unwrap(), {handle}).is_ok());
        BuildOptions options;
        options.keepUnknownSections = false;
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 注解目标已被删除。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 foo = findMethodByName(*file, "foo");
        ASSERT_NE(foo, DexFile::kNoIndex);
        const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/A;");
        ASSERT_NE(handle, DexFile::kNoIndex);
        ASSERT_TRUE(file->setMethodAnnotations(0, foo, {handle}).is_ok());
        BuildOptions options;
        options.keepUnknownSections = false;
        options.removedMethods.push_back(foo);
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 参数注解个数与 proto 不符。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 foo = findMethodByName(*file, "foo");
        const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/A;");
        ASSERT_NE(foo, DexFile::kNoIndex);
        ASSERT_NE(handle, DexFile::kNoIndex);
        // ()V 却给了 1 组参数注解。
        ASSERT_TRUE(file->setParameterAnnotations(0, foo, {{handle}}).is_ok());
        BuildOptions options;
        options.keepUnknownSections = false;
        const auto built = buildDex(*file, options);
        ASSERT_TRUE(built.is_err());
        EXPECT_EQ(built.unwrap_err(), WriteError::InvalidModel);
    }
    // 池内容悬垂：类型索引越界、元素名越界、值索引越界。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);

        AnnotationItem badType;
        badType.annotation.typeIdx = file->typeCount();
        EXPECT_EQ(file->addAnnotationItem(badType).unwrap_err(), ReadError::BadIndex);

        AnnotationItem badName;
        badName.annotation.typeIdx = 0;
        AnnotationElement element;
        element.nameIdx = file->stringCount();
        badName.annotation.elements.push_back(element);
        EXPECT_EQ(file->addAnnotationItem(badName).unwrap_err(), ReadError::BadIndex);

        AnnotationItem badValue;
        badValue.annotation.typeIdx = 0;
        element.nameIdx = 0;
        element.value.type = EncodedValueType::String;
        element.value.index = file->stringCount();
        badValue.annotation.elements.push_back(element);
        EXPECT_EQ(file->addAnnotationItem(badValue).unwrap_err(), ReadError::BadIndex);
    }
    // 覆盖 API 自身的句柄校验。
    {
        std::unique_ptr<DexFile> file = readFixture();
        ASSERT_NE(file, nullptr);
        const ca::u32 dangling = 99;
        EXPECT_EQ(file->setClassAnnotations(0, {dangling}).unwrap_err(), ReadError::BadIndex);
        EXPECT_EQ(file->setFieldAnnotations(0, 0, {dangling}).unwrap_err(), ReadError::BadIndex);
        EXPECT_EQ(file->setClassAnnotations(9, {}).unwrap_err(), ReadError::BadIndex);
    }
}

TEST(DexAnnotationWrite, DedupesAnnotationItemsByContent)
{
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);

    AnnotationItem item;
    item.visibility = 1;
    item.annotation.typeIdx = 0;
    const auto first = file->addAnnotationItem(item);
    ASSERT_TRUE(first.is_ok());

    AnnotationItem same = item;
    const auto again = file->addAnnotationItem(same);
    ASSERT_TRUE(again.is_ok());
    EXPECT_EQ(again.unwrap(), first.unwrap());

    AnnotationElement element;
    element.nameIdx = 0;
    element.value.type = EncodedValueType::Boolean;
    element.value.boolean = true;
    element.value.valueArg = 0;
    item.annotation.elements.push_back(element);
    const auto grown = file->addAnnotationItem(item);
    ASSERT_TRUE(grown.is_ok());
    EXPECT_NE(grown.unwrap(), first.unwrap());
    EXPECT_NE(file->ownedAnnotationItem(first.unwrap()), nullptr);
    EXPECT_EQ(file->ownedAnnotationItem(grown.unwrap())->annotation.elements.size(), 1u);
    EXPECT_EQ(file->ownedAnnotationItem(file->ownedAnnotationItemCount()), nullptr);
}

TEST(DexAnnotationWrite, RebuildsSourceAnnotationsWithoutEdits)
{
    // 第一轮：造一个带类/方法/参数注解的 dex（含新字符串，索引起变化）。
    std::unique_ptr<DexFile> file = readFixture();
    ASSERT_NE(file, nullptr);
    const ca::u32 handle = internAuthorAnnotation(*file, "Ltest/Author;");
    ASSERT_NE(handle, DexFile::kNoIndex);
    const ca::u32 foo = findMethodByName(*file, "foo");
    ASSERT_NE(foo, DexFile::kNoIndex);
    ASSERT_TRUE(file->setClassAnnotations(0, {handle}).is_ok());
    ASSERT_TRUE(file->setMethodAnnotations(0, foo, {handle}).is_ok());

    BuildOptions seeded;
    seeded.keepUnknownSections = false;
    auto built = buildDex(*file, seeded);
    ASSERT_TRUE(built.is_ok()) << to_string(built.unwrap_err());
    const std::vector<ca::u8> annotated = std::move(built).unwrap();

    // 第二轮：无任何覆盖的普通重建（默认保留未知 section），源注解应原样保留。
    auto reparsed = readDex(dex_test::asSlice(annotated));
    ASSERT_TRUE(reparsed.is_ok()) << to_string(reparsed.unwrap_err());
    std::unique_ptr<DexFile> second = std::move(reparsed).unwrap();
    auto rebuilt = buildDex(*second);
    ASSERT_TRUE(rebuilt.is_ok()) << to_string(rebuilt.unwrap_err());
    EXPECT_EQ(rebuilt.unwrap(), annotated);  // 固定点：字节一致

    auto third = readDex(dex_test::asSlice(rebuilt.unwrap()));
    ASSERT_TRUE(third.is_ok());
    std::unique_ptr<DexFile> parsed3 = std::move(third).unwrap();
    const auto directory = parsed3->annotationsDirectory(parsed3->classDefs[0].annotationsOff);
    ASSERT_TRUE(directory.is_ok());
    EXPECT_NE(directory.unwrap()->classAnnotationsOff, 0u);
    ASSERT_EQ(directory.unwrap()->methodAnnotations.size(), 1u);
    const auto set = parsed3->annotationSet(directory.unwrap()->classAnnotationsOff);
    ASSERT_TRUE(set.is_ok());
    ASSERT_EQ(set.unwrap()->annotationOffs.size(), 1u);
    const auto item = parsed3->annotationItem(set.unwrap()->annotationOffs[0]);
    ASSERT_TRUE(item.is_ok());
    const auto descriptor = parsed3->typeDescriptor(item.unwrap()->annotation.typeIdx);
    ASSERT_TRUE(descriptor.is_ok());
    EXPECT_EQ(descriptor.unwrap().as_std_view(), "Ltest/Author;");
}
