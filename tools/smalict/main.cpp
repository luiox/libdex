/// @file        main.cpp
/// @brief       smalict：libsmali 的 CLI——反汇编 dex 目录与汇编 smali 目录。
///
/// 用法：
///   smalict dis <file.dex> <out-dir>     每类一个 .smali 文件
///   smalict asm <smali-dir> <out.dex>    目录内 *.smali 汇编为一份 dex
///   smalict roundtrip <file.dex> <tmp-dir>
///       反汇编 → 汇编 → buildDex → 重读 → 反汇编，要求文本逐字节一致。
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "dex/core/builder.hpp"
#include "dex/core/reader.hpp"
#include "smali/assemble.hpp"
#include "smali/disassemble.hpp"

namespace {

using dex::core::ByteSlice;
using dex::core::DexFile;
using dex::core::ReadError;
using dex::core::ReadOptions;
using dex::core::Result;
using dex::core::WriteError;

bool readFile(const char* path, std::vector<ca::u8>* out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string s = ss.str();
    out->assign(s.begin(), s.end());
    return true;
}

bool writeFile(const char* path, const std::string& data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return bool(f);
}

int cmdDis(int argc, char** argv)
{
    if (argc != 4) {
        std::fprintf(stderr, "usage: smalict dis <file.dex> <out-dir>\n");
        return 2;
    }
    std::vector<ca::u8> bytes;
    if (!readFile(argv[2], &bytes)) {
        std::fprintf(stderr, "smalict: cannot read %s\n", argv[2]);
        return 1;
    }
    Result<std::unique_ptr<DexFile>, ReadError> parsed =
        readDex(ByteSlice{bytes.data(), bytes.size()}, ReadOptions{});
    if (parsed.is_err()) {
        std::fprintf(stderr, "smalict: readDex failed: %s\n",
                     dex::core::to_string(parsed.unwrap_err()));
        return 1;
    }
    std::unique_ptr<DexFile> dex = std::move(parsed).unwrap();
    const Result<std::vector<std::pair<std::string, std::string>>, dex::smali::SmaliError>
        files = dex::smali::disassembleAll(*dex);
    if (files.is_err()) {
        std::fprintf(stderr, "smalict: disassemble failed: %s\n",
                     dex::smali::to_string(files.unwrap_err()));
        return 1;
    }
    for (const auto& [name, text] : files.unwrap()) {
        const std::string path = std::string(argv[3]) + "/" + name;
        if (!writeFile(path.c_str(), text)) {
            std::fprintf(stderr, "smalict: cannot write %s\n", path.c_str());
            return 1;
        }
        std::printf("dis %s\n", path.c_str());
    }
    std::printf("smalict: %zu class(es) -> %s\n", files.unwrap().size(), argv[3]);
    return 0;
}

int cmdAsm(int argc, char** argv)
{
    if (argc != 4) {
        std::fprintf(stderr, "usage: smalict asm <smali-dir> <out.dex>\n");
        return 2;
    }
    std::unique_ptr<DexFile> dex = DexFile::createEmpty(35);
    dex::smali::SmaliAssembler assembler(*dex);
    // 枚举目录（简单起见用 system 通配不可移植；这里靠 stdin 或 shell 展开
    // 都太绕，直接用 C++17 的 <filesystem>）。
    std::vector<std::string> files;
    for (const auto& entry : std::filesystem::directory_iterator(argv[2])) {
        if (entry.is_regular_file() && entry.path().extension() == ".smali") {
            files.push_back(entry.path().string());
        }
    }
    std::sort(files.begin(), files.end());
    for (const std::string& path : files) {
        std::vector<ca::u8> raw;
        if (!readFile(path.c_str(), &raw)) {
            std::fprintf(stderr, "smalict: cannot read %s\n", path.c_str());
            return 1;
        }
        std::string text(raw.begin(), raw.end());
        const Result<ca::u32, dex::smali::AsmError> r = assembler.assembleClass(text);
        if (r.is_err()) {
            std::fprintf(stderr, "smalict: %s line %u: %s (%s)\n", path.c_str(),
                         r.unwrap_err().line,
                         dex::smali::to_string(r.unwrap_err().code),
                         r.unwrap_err().detail.c_str());
            return 1;
        }
        std::printf("asm %s -> class %u\n", path.c_str(), r.unwrap());
    }
    const Result<std::vector<ca::u8>, WriteError> built = buildDex(*dex, assembler.options());
    if (built.is_err()) {
        std::fprintf(stderr, "smalict: buildDex failed: %s\n",
                     dex::core::to_string(built.unwrap_err()));
        return 1;
    }
    const std::string outData(built.unwrap().begin(), built.unwrap().end());
    if (!writeFile(argv[3], outData)) {
        std::fprintf(stderr, "smalict: cannot write %s\n", argv[3]);
        return 1;
    }
    std::printf("smalict: %zu class(es) -> %s (%zu bytes)\n", files.size(), argv[3],
                outData.size());
    return 0;
}

int cmdRoundtrip(int argc, char** argv)
{
    if (argc != 4) {
        std::fprintf(stderr, "usage: smalict roundtrip <file.dex> <tmp-dir>\n");
        return 2;
    }
    std::vector<ca::u8> bytes;
    if (!readFile(argv[2], &bytes)) {
        std::fprintf(stderr, "smalict: cannot read %s\n", argv[2]);
        return 1;
    }
    Result<std::unique_ptr<DexFile>, ReadError> parsed =
        readDex(ByteSlice{bytes.data(), bytes.size()}, ReadOptions{});
    if (parsed.is_err()) {
        std::fprintf(stderr, "smalict: readDex failed\n");
        return 1;
    }
    std::unique_ptr<DexFile> dex = std::move(parsed).unwrap();
    const Result<std::vector<std::pair<std::string, std::string>>, dex::smali::SmaliError>
        t1 = dex::smali::disassembleAll(*dex);
    if (t1.is_err()) {
        std::fprintf(stderr, "smalict: disassemble failed: %s\n",
                     dex::smali::to_string(t1.unwrap_err()));
        return 1;
    }

    std::unique_ptr<DexFile> fresh = DexFile::createEmpty(35);
    dex::smali::SmaliAssembler assembler(*fresh);
    for (const auto& [name, text] : t1.unwrap()) {
        const Result<ca::u32, dex::smali::AsmError> r = assembler.assembleClass(text);
        if (r.is_err()) {
            std::fprintf(stderr, "smalict: %s line %u: %s (%s)\n", name.c_str(),
                         r.unwrap_err().line,
                         dex::smali::to_string(r.unwrap_err().code),
                         r.unwrap_err().detail.c_str());
            return 1;
        }
    }
    const Result<std::vector<ca::u8>, WriteError> built = buildDex(*fresh, assembler.options());
    if (built.is_err()) {
        std::fprintf(stderr, "smalict: buildDex failed: %s\n",
                     dex::core::to_string(built.unwrap_err()));
        return 1;
    }
    Result<std::unique_ptr<DexFile>, ReadError> reparsed =
        readDex(ByteSlice{built.unwrap().data(), built.unwrap().size()}, ReadOptions{});
    if (reparsed.is_err()) {
        std::fprintf(stderr, "smalict: reparsed dex unreadable\n");
        return 1;
    }
    std::unique_ptr<DexFile> dex2 = std::move(reparsed).unwrap();
    const Result<std::vector<std::pair<std::string, std::string>>, dex::smali::SmaliError>
        t2 = dex::smali::disassembleAll(*dex2);
    if (t2.is_err()) {
        std::fprintf(stderr, "smalict: re-disassemble failed: %s\n",
                     dex::smali::to_string(t2.unwrap_err()));
        return 1;
    }
    if (t1.unwrap().size() != t2.unwrap().size()) {
        std::fprintf(stderr, "smalict: class count differs\n");
        return 1;
    }
    {
        // 类顺序可因重排不同；按名字对齐比较。
        std::map<std::string, std::string> t2ByName;
        for (const auto& [name, text] : t2.unwrap()) {
            t2ByName.emplace(name, text);
        }
        for (const auto& [name, text] : t1.unwrap()) {
            auto it = t2ByName.find(name);
            if (it == t2ByName.end()) {
                std::fprintf(stderr, "smalict: missing class %s in rebuild\n",
                             name.c_str());
                return 1;
            }
            if (it->second != text) {
                std::fprintf(stderr, "smalict: text differs for %s\n", name.c_str());
                const std::string a = argv[3];
                writeFile((a + "/t1_" + name).c_str(), text);
                writeFile((a + "/t2_" + name).c_str(), it->second);
                return 1;
            }
        }
    }
    std::printf("smalict roundtrip ok: %s (%zu classes, %zu bytes)\n", argv[2],
                t1.unwrap().size(), built.unwrap().size());
    return 0;
}

}   // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: smalict dis|asm|roundtrip <args>\n"
                     "  dis <file.dex> <out-dir>\n"
                     "  asm <smali-dir> <out.dex>\n"
                     "  roundtrip <file.dex> <tmp-dir>\n");
        return 2;
    }
    const std::string cmd = argv[1];
    if (cmd == "dis") {
        return cmdDis(argc, argv);
    }
    if (cmd == "asm") {
        return cmdAsm(argc, argv);
    }
    if (cmd == "roundtrip") {
        return cmdRoundtrip(argc, argv);
    }
    std::fprintf(stderr, "smalict: unknown command %s\n", cmd.c_str());
    return 2;
}
