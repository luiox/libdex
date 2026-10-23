/// @file        main.cpp
/// @brief       libdex 命令行：整文件重建与合成 fixture 生成。
///
/// `rebuild` 走 `readDex` → `buildDex` 的公开路径，供对拍脚本和人工排查使用；
/// `fixture` 输出与单测相同的 035 合成样本，CI 的对拍门禁不依赖外部语料。
#include <cstdio>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "dex/dex.hpp"
#include "dex_fixture.hpp"

namespace {

int usage()
{
    std::fprintf(stderr,
                 "usage: dexbuild rebuild <input.dex> <output.dex>\n"
                 "       dexbuild fixture <output.dex>\n");
    return 2;
}

bool readFile(const std::string& path, std::vector<ca::u8>& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "dexbuild: cannot open %s\n", path.c_str());
        return false;
    }
    const std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    out.assign(raw.begin(), raw.end());
    return true;
}

bool writeFile(const std::string& path, ca::core::ByteSlice bytes)
{
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        std::fprintf(stderr, "dexbuild: cannot create %s\n", path.c_str());
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(out);
}

}   // namespace

int main(int argc, char** argv)
{
    if (argc < 3) {
        return usage();
    }

    const std::string command = argv[1];
    if (command == "fixture" && argc == 3) {
        const std::vector<ca::u8> bytes = dex_test::makeHelloDex();
        return writeFile(argv[2], dex_test::asSlice(bytes)) ? 0 : 1;
    }

    if (command == "rebuild" && argc == 4) {
        std::vector<ca::u8> bytes;
        if (!readFile(argv[2], bytes)) {
            return 1;
        }

        auto parsed = dex::core::readDex(ca::core::ByteSlice{bytes.data(), bytes.size()});
        if (parsed.is_err()) {
            std::fprintf(stderr, "dexbuild: %s: %s\n", argv[2],
                         dex::core::to_string(parsed.unwrap_err()));
            return 1;
        }
        std::unique_ptr<dex::core::DexFile> file = std::move(parsed).unwrap();

        auto built = dex::core::buildDex(*file);
        if (built.is_err()) {
            std::fprintf(stderr, "dexbuild: %s: %s\n", argv[2],
                         dex::core::to_string(built.unwrap_err()));
            return 1;
        }
        const std::vector<ca::u8> output = std::move(built).unwrap();
        if (!writeFile(argv[3], ca::core::ByteSlice{output.data(), output.size()})) {
            return 1;
        }

        std::fprintf(stdout, "%s: %zu -> %zu bytes, %u classes, %u methods\n", argv[2],
                     bytes.size(), output.size(), file->classCount(), file->methodCount());
        return 0;
    }

    return usage();
}
