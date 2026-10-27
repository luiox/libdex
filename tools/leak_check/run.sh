#!/usr/bin/env sh
# ASan 泄漏门：先自证插桩生效，再对语料走查（读→全解码→重建→重读）。
#
# 用法：tools/leak_check/run.sh <dex> [<dex>...]
#   需先 xmake f --with_asan=y && xmake build libdex_leak_check。
#   Windows 的 MSVC ASan 报告后退出码仍可为 0，因此以报告中是否出现
#   "ERROR: AddressSanitizer" 为准；自检阶段找不到报告即视为门是假的。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LC=$(find "$ROOT/build" -maxdepth 4 -type f \( -name libdex_leak_check -o -name libdex_leak_check.exe \) 2>/dev/null | head -n 1)
if [ -z "$LC" ]; then
    echo "leak_check: binary not found; xmake f --with_asan=y && xmake build libdex_leak_check" >&2
    exit 2
fi

# MSVC 动态运行库不在默认 PATH；找到它加进来。
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*)
        dll=$(find "/c/Program Files/Microsoft Visual Studio" \
            -name clang_rt.asan_dynamic-x86_64.dll 2>/dev/null | head -n 1)
        if [ -n "$dll" ]; then
            PATH="$(dirname "$dll"):$PATH"
            export PATH
        fi
        ;;
esac

if [ $# -lt 1 ]; then
    echo "usage: $0 <dex> [<dex>...]" >&2
    exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if LIBDEX_ASAN_SELFTEST=1 "$LC" "$1" >/dev/null 2>"$tmp/self.txt"; then
    :
fi
if ! grep -q "AddressSanitizer" "$tmp/self.txt"; then
    echo "leak_check: FAIL selftest — asan instrumentation not effective" >&2
    cat "$tmp/self.txt" >&2
    exit 1
fi
echo "leak_check: selftest ok (instrumentation effective)"

if "$LC" "$@" >"$tmp/walk.txt" 2>"$tmp/walk.err"; then
    :
fi
if grep -q "ERROR: AddressSanitizer" "$tmp/walk.err"; then
    echo "leak_check: FAIL — asan report during walk" >&2
    grep -A25 "ERROR: AddressSanitizer" "$tmp/walk.err" | head -40 >&2
    exit 1
fi
cat "$tmp/walk.txt"
echo "leak_check: ok ($# file(s), no asan reports)"
