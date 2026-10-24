#!/usr/bin/env sh
# 对拍：把输入 dex 用 libdex 重建，再用 baksmali 分别反汇编原文与重建产物，
# 要求两份 smali 文本完全一致。
#
# 用法：tools/oracle/check.sh <dex-file> [dexbuild]
#   dexbuild 可省略，脚本会在 build/ 下查找；也可用 DEXBUILD 环境变量指定。
#   LIBDEX_ORACLE_CACHE 指定 jar 缓存目录（默认 <repo>/.oracle-cache）。
#   LIBDEX_ORACLE_KEEP=1 保留临时目录。
#
# 依赖：java 17+、curl（或 wget）、diff、mktemp。jar 从 Maven Central 拉取并
# 按版本缓存；baksmali 固定为 BAKSMALI_VERSION，避免上游漂移改变输出。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BAKSMALI_VERSION=${BAKSMALI_VERSION:-2.5.2}

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) PATHSEP=';' ;;
    *) PATHSEP=':' ;;
esac

# Windows 的 java.exe 不认识 MSYS 的 /tmp 与 /c 路径；交给 Java 前转成 C:/ 形态。
native_path() {
    if [ "$PATHSEP" = ";" ] && command -v cygpath >/dev/null 2>&1; then
        cygpath -m -- "$1"
    else
        printf '%s' "$1"
    fi
}
CACHE=${LIBDEX_ORACLE_CACHE:-"$ROOT/.oracle-cache"}
API=${LIBDEX_ORACLE_API:-30}
JAVA=${JAVA:-java}

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <dex-file> [dexbuild]" >&2
    exit 2
fi

DEX=$1
if [ ! -f "$DEX" ]; then
    echo "oracle: no such dex: $DEX" >&2
    exit 2
fi

DEXBUILD=${2:-${DEXBUILD:-}}
if [ -z "$DEXBUILD" ]; then
    DEXBUILD=$(find "$ROOT/build" -maxdepth 4 -type f \
        \( -name dexbuild -o -name dexbuild.exe \) 2>/dev/null | head -n 1)
fi
if [ -z "$DEXBUILD" ] || [ ! -x "$DEXBUILD" ]; then
    echo "oracle: dexbuild not found; run 'xmake build dexbuild' or pass its path" >&2
    exit 2
fi

command -v "$JAVA" >/dev/null 2>&1 || {
    echo "oracle: java not found" >&2
    exit 2
}

# Maven Central 拉取；curl 与 wget 二选一。
download() {
    url=$1
    out=$2
    if [ -s "$out" ]; then
        return 0
    fi
    echo "oracle: fetching $(basename "$out")" >&2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 20 -o "$out.part" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out.part" "$url"
    else
        echo "oracle: curl or wget is required" >&2
        exit 2
    fi
    mv "$out.part" "$out"
}

mkdir -p "$CACHE"
BASE=https://repo1.maven.org/maven2
JARS="baksmali-$BAKSMALI_VERSION.jar dexlib2-$BAKSMALI_VERSION.jar util-$BAKSMALI_VERSION.jar guava-27.1-android.jar jcommander-1.64.jar jsr305-3.0.2.jar failureaccess-1.0.1.jar"

download "$BASE/org/smali/baksmali/$BAKSMALI_VERSION/baksmali-$BAKSMALI_VERSION.jar" \
    "$CACHE/baksmali-$BAKSMALI_VERSION.jar"
download "$BASE/org/smali/dexlib2/$BAKSMALI_VERSION/dexlib2-$BAKSMALI_VERSION.jar" \
    "$CACHE/dexlib2-$BAKSMALI_VERSION.jar"
download "$BASE/org/smali/util/$BAKSMALI_VERSION/util-$BAKSMALI_VERSION.jar" \
    "$CACHE/util-$BAKSMALI_VERSION.jar"
download "$BASE/com/google/guava/guava/27.1-android/guava-27.1-android.jar" \
    "$CACHE/guava-27.1-android.jar"
download "$BASE/com/beust/jcommander/1.64/jcommander-1.64.jar" \
    "$CACHE/jcommander-1.64.jar"
download "$BASE/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar" \
    "$CACHE/jsr305-3.0.2.jar"
download "$BASE/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar" \
    "$CACHE/failureaccess-1.0.1.jar"

CP=
for jar in $JARS; do
    if [ -n "$CP" ]; then
        CP="$CP$PATHSEP"
    fi
    CP="$CP$(native_path "$CACHE/$jar")"
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/libdex-oracle.XXXXXX")
cleanup() {
    if [ "${LIBDEX_ORACLE_KEEP:-0}" = "1" ] || [ "${ORACLE_FAILED:-0}" = "1" ]; then
        echo "oracle: artifacts kept at $TMP" >&2
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT INT TERM

"$DEXBUILD" rebuild "$DEX" "$TMP/rebuilt.dex"

DEX_NATIVE=$(native_path "$DEX")
REBUILT_NATIVE=$(native_path "$TMP/rebuilt.dex")
"$JAVA" -cp "$CP" org.jf.baksmali.Main d -a "$API"     -o "$(native_path "$TMP/original")" "$DEX_NATIVE"
"$JAVA" -cp "$CP" org.jf.baksmali.Main d -a "$API"     -o "$(native_path "$TMP/rebuilt")" "$REBUILT_NATIVE"

# baksmali 按 class_data 顺序输出方法块；canonical 重建按 DEX 规范重排
# method_ids 后该顺序会变。方法块顺序不是语义，先按块排序再 diff；字段、
# 注解与指令文本仍逐字节比较。
sort_methods() {
    find "$1" -type f -name '*.smali' | while IFS= read -r file; do
        awk '
            /^\.method / && !inmethod {
                inmethod = 1
                block = $0 "\n"
                next
            }
            inmethod {
                block = block $0 "\n"
                if ($0 == ".end method") {
                    blocks[++count] = block
                    inmethod = 0
                }
                next
            }
            count == 0 { prefix = prefix $0 "\n" }
            END {
                for (i = 1; i <= count; ++i) {
                    for (j = i + 1; j <= count; ++j) {
                        if (blocks[j] < blocks[i]) {
                            swap = blocks[i]
                            blocks[i] = blocks[j]
                            blocks[j] = swap
                        }
                    }
                }
                printf "%s", prefix
                for (i = 1; i <= count; ++i) {
                    printf "%s", blocks[i]
                }
            }
        ' "$file" > "$file.sorted" && mv "$file.sorted" "$file"
    done
}
sort_methods "$TMP/original"
sort_methods "$TMP/rebuilt"

if diff -ru "$TMP/original" "$TMP/rebuilt" > "$TMP/diff.txt"; then
    COUNT=$(find "$TMP/rebuilt" -type f -name '*.smali' | wc -l | tr -d ' ')
    echo "oracle ok: $DEX ($COUNT classes)"
else
    ORACLE_FAILED=1
    echo "oracle mismatch: $DEX" >&2
    sed -n '1,160p' "$TMP/diff.txt" >&2
    exit 1
fi
