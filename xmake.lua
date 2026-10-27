-- libdex：DEX 字节核（L1）——单 DexFile lazy DOM + 保真写回。
-- 设计见 doc/design.md；契约与 libjbc core 同族。
--
-- 依赖：libca（luiox-repo git 直连包）与 libjstr（MUTF-8 容器）经包仓消费；
-- gtest 仅测试态。libca 模块集取 luiox 家族统一超集，避免同一消费图内
-- 出现多个 (版本, configs) 不同的 libca 实例。

set_project("libdex")
set_version("0.0.1")
set_license("MIT")
set_languages("cxx17")
set_allowedplats("windows", "linux", "macosx")

add_repositories("luiox-repo https://github.com/luiox/luiox-repo.git")

-- 构建开关：独立仓默认开测试；只构建库本体用 xmake f --with_tests=n。
option("with_tests")
    set_default(true)
    set_showmenu(true)
    set_description("Build libdex_unittest (pulls gtest).")
option_end()

-- ASan 泄漏门：独立 target、不与 gtest 同链（MSVC /fsanitize=address 改
-- STL ABI）。xmake f --with_asan=y 时插桩；不开也能编但门是假的。
option("with_asan")
    set_default(false)
    set_showmenu(true)
    set_description("Instrument libdex_leak_check with AddressSanitizer.")
option_end()

-- 模块集与 mjbase/mjt 的 LUIOX_LIBCA_MODULES 保持一致。libjstr 包定义把
-- libca 钉在同一超集上；这里取同一份，requireconfs 只负责版本收敛。
LUIOX_LIBCA_VERSION = "0.0.16"
LUIOX_LIBCA_MODULES = "core,crypto,str,fs,env,io,json,net,http,process,opt,thread,log,zip,resources,i18n,test"

if has_config("with_tests") then
    add_requires("gtest")
end
add_requires("libca " .. LUIOX_LIBCA_VERSION, {configs = {modules = LUIOX_LIBCA_MODULES}})
add_requires("libjstr 0.0.4")
add_requireconfs("libjstr.libca", {version = LUIOX_LIBCA_VERSION, configs = {modules = LUIOX_LIBCA_MODULES}})
-- libca_zip 的消费方自带 zlib（libca 包不传递声明，libjstr 的包定义声明了它）。
add_requires("zlib")

-- libca_* 目标名垫片：库内消费点写 add_deps("libca_core"/"libca_str"/
-- "libca_crypto")，由这里统一转发到 libca 包。
for _, m in ipairs({"core", "str", "crypto"}) do
target("libca_" .. m)
    set_kind("phony")
    add_packages("libca", {public = true})
target_end()
end

-- 链接闭包助手：显式列闭包，linux 进 linkgroups 免序，其余平台裸
-- add_links（MSVC link.exe 对库顺序不敏感）。
function binary_link_closure(...)
    local libs = {...}
    local unpack = table.unpack or unpack
    add_links(unpack(libs))
    if is_plat("linux") then
        add_linkgroups(unpack(libs))
    end
end

-- 禁用 RTTI：所有 dynamic_cast 替换为 typed 判型；异常同样关闭。
if is_plat("windows") then
    add_cxflags("/GR-", {tools = "cl"})
    add_cxflags("/EHa", {tools = "cl"})
    add_cxflags("/wd4541", {tools = "cl"})
    set_exceptions("none")
else
    add_cxxflags("-fno-rtti")
end

if is_host("windows") then
    set_plat("windows")
    set_toolchains("msvc")
end

target("libdex")
    set_kind("static")
    set_group("libs")

    add_deps("libca_core", "libca_str", "libca_crypto")
    add_packages("libjstr", {public = true})
    add_files("src/dex/core/*.cpp", "src/dex/type/*.cpp")
    add_headerfiles("src/(dex/**.hpp)")
    add_includedirs("src", {public = true})

    set_languages("cxx17")

    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

    -- ASan 泄漏门要求全闭包插桩（MSVC 下混链即 LNK1319）；默认关闭，
    -- 只有 leak_check 场景开 --with_asan=y。
    if has_config("with_asan") then
        if is_plat("windows") then
            add_cxflags("/fsanitize=address", {tools = "cl"})
            -- 预编译依赖（libca 包）未插桩：关容器注解对齐混链检查。
            add_defines("_DISABLE_STRING_ANNOTATION", "_DISABLE_VECTOR_ANNOTATION")
        else
            add_cxflags("-fsanitize=address", "-fno-omit-frame-pointer")
        end
    end

-- 对拍与人工排查用 CLI：与单测共享合成 fixture，不默认构建。
-- libsmali：DEX 与 smali 文本互转（依赖 libdex）。
target("libsmali")
    set_kind("static")
    set_group("libs")

    add_deps("libdex")
    add_packages("libjstr", {public = true})
    add_files("src/smali/*.cpp")
    add_headerfiles("src/(smali/**.hpp)")
    add_includedirs("src", {public = true})
    set_languages("cxx17")

    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

    -- ASan 全闭包要求：与 libdex 同步插桩（见 libdex 目标内的注释）。
    if has_config("with_asan") then
        if is_plat("windows") then
            add_cxflags("/fsanitize=address", {tools = "cl"})
            add_defines("_DISABLE_STRING_ANNOTATION", "_DISABLE_VECTOR_ANNOTATION")
        else
            add_cxflags("-fsanitize=address", "-fno-omit-frame-pointer")
        end
    end

    if is_mode("releasedbg") then
        add_cxflags("/Zi", "/FS", {force = true})
        add_ldflags("/DEBUG", {force = true})
    end

target("dexbuild")
    set_kind("binary")
    set_group("tools")
    set_default(false)

    add_deps("libdex")
    binary_link_closure("libdex", "libjstr", "libca_crypto", "libca_str", "libca_core")
    add_files("tools/dexbuild/*.cpp", "test/unittest/dex_fixture.cpp")
    add_includedirs("src", "test/unittest")

    if is_plat("linux") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

-- 大文件性能基线：合成 10 万方法级 dex，计时解析/走查/重建（M5）。
target("dexperf")
    set_kind("binary")
    set_group("tools")
    set_default(false)

    add_deps("libdex")
    binary_link_closure("libdex", "libjstr", "libca_crypto", "libca_str", "libca_core")
    add_files("tools/perf_baseline/*.cpp")
    add_includedirs("src")

    if is_plat("linux") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

-- ASan 泄漏门：真实 dex 读 → 全解码 → 重建 → 重读，零报告。
target("libdex_leak_check")
    set_kind("binary")
    set_group("tools")
    set_default(false)

    add_deps("libdex", "libsmali")
    binary_link_closure("libsmali", "libdex", "libjstr", "libca_crypto", "libca_str", "libca_core")
    add_files("tools/leak_check/*.cpp")
    add_includedirs("src")

    if has_config("with_asan") then
        if is_plat("windows") then
            add_cxflags("/fsanitize=address", {tools = "cl"})
            add_defines("_DISABLE_STRING_ANNOTATION", "_DISABLE_VECTOR_ANNOTATION")
            add_ldflags("/fsanitize=address", {tools = "link"})
        else
            add_cxflags("-fsanitize=address", "-fno-omit-frame-pointer")
            add_ldflags("-fsanitize=address")
        end
    end

    if is_plat("linux") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

-- smalict：libsmali 的 CLI（反汇编/汇编/往返自检）。
target("smalict")
    set_kind("binary")
    set_group("tools")
    set_default(false)

    add_deps("libdex", "libsmali")
    binary_link_closure("libsmali", "libdex", "libjstr", "libca_crypto", "libca_str", "libca_core")
    add_files("tools/smalict/*.cpp")
    add_includedirs("src")

    if is_plat("linux") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end

-- gtest 面随 with_tests 门控：默认配置不定义本 target、不拉 gtest。
if has_config("with_tests") then
target("libdex_unittest")
    set_kind("binary")
    set_group("libs/test")
    set_default(false)

    add_deps("libdex", "libsmali")
    -- xmake 3.x 不会自动链静态依赖的二级传递闭包；显式列全。
    binary_link_closure("libsmali", "libdex", "libjstr", "libca_crypto", "libca_str", "libca_core")
    add_packages("gtest")
    add_files("test/unittest/*.cpp")
    add_includedirs("src")
    set_rundir("$(projectdir)")

    if is_plat("linux") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        add_cxflags("/utf-8", {tools = "cl"})
    end
end
