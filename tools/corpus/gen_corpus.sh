#!/usr/bin/env bash
# 语料矩阵生成：用本机 Android SDK 的 d8 从 Java 样本产出 035/037/038/039
# 版本的 .dex 并给出 SHA-256 清单。产物不入库；复现入库的是样本源码与本脚本。
#
# 用法：
#   tools/corpus/gen_corpus.sh [输出目录]          # 默认 build/corpus
#   ANDROID_HOME=/path/to/sdk tools/corpus/gen_corpus.sh
#
# 版本来源（d8 由 --min-api 推 dex 版本）：
#   035: --min-api 14（api < 24）
#   037: --min-api 24
#   038: --min-api 26
#   039: --min-api 28（api >= 28 的上限，d8 不产出更高）
# 040/041 不在生成范围：040 与 039 无结构差异、标准工具不产出（只有设备上
# 的 ART 会写）；041 是 container dex（.cdex/.vdex 内部布局），由设备提取：
#   adb pull /data/dalvik-cache/arm64/<pkg>@...@classes.dex
# 提取物只提交哈希清单，不入库。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${1:-$script_dir/../../build/corpus}"
sdk="${ANDROID_HOME:-/d/sdk/AndroidSdk}"

# 选择最新的 build-tools（d8 在 31+ 足够）。
d8=""
for bt in $(ls "$sdk/build-tools" 2>/dev/null | sort -r); do
    candidate="$sdk/build-tools/$bt/d8.bat"
    [ -f "$candidate" ] || candidate="$sdk/build-tools/$bt/d8"
    if [ -f "$candidate" ]; then d8="$candidate"; break; fi
done
if [ -z "$d8" ]; then
    echo "error: d8 not found under $sdk/build-tools (set ANDROID_HOME)" >&2
    exit 1
fi
if ! command -v javac >/dev/null 2>&1; then
    echo "error: javac (17+) required" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
classes_dir="$work/classes"
mkdir -p "$classes_dir"

# javac 以最低目标编译，保证字节码在任何 min-api 下都能被 d8 接受。
(cd "$script_dir/samples" && javac -encoding UTF-8 -d "$classes_dir" --release 8 *.java)

mkdir -p "$out_dir"
gen() {  # gen <min-api> <name>
    local api="$1" name="$2"
    local dir="$work/out$api"
    mkdir -p "$dir"
    (cd "$classes_dir" && "$d8" --release --min-api "$api" --output "$dir" ./*.class)
    cp "$dir/classes.dex" "$out_dir/$name.dex"
    local magic
    magic="$(head -c 8 "$out_dir/$name.dex" | tr -d '\n' | tail -c 4 | tr -d '\0')"
    echo "$name.dex  magic=$magic"
}

gen 14 corpus_035_sample
gen 24 corpus_037_sample
gen 26 corpus_038_sample
gen 28 corpus_039_sample

manifest="$out_dir/manifest.sha256"
(cd "$out_dir" && sha256sum ./*.dex) > "$manifest"
echo "--- manifest ($manifest)"
cat "$manifest"
echo "done: $(ls "$out_dir" | grep -c '\.dex$') dex files in $out_dir"
echo "usage: LIBDEX_REAL_DEX_DIR=$(cd "$out_dir" && pwd) xmake run libdex_unittest"
