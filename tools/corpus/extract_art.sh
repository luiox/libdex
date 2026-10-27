#!/usr/bin/env bash
# 040/041 语料提取：从常驻设备/模拟器拉取 ART 产物（vdex/cdex），切出内嵌
# dex，按 magic 分类为 040（标准 dex）与 041（container 字段 / compact dex），
# 产出 SHA-256 清单与提取报告。产物不入库；入库的是本脚本与清单。
#
# 前提：
#   - adb 可达的设备或模拟器（LIBDEX_ADB / LIBDEX_ART_SERIAL 同 check.sh）；
#   - /data 分区可读：userdebug/eng 或已解锁设备、`adb root` 可用的模拟器。
#     用户构建读不到 dalvik-cache，此时脚本明确报错，不静默跳过。
#
# 用法：tools/corpus/extract_art.sh [输出目录]      # 默认 build/corpus
#   LIBDEX_EXTRACT_LIMIT 限制拉取的候选文件数（默认 16）。
#
# 提取语义：vdex 只是容器，内嵌的 dex/cdex 段按其自身 header 的 file_size
# 切出；magic 与版本以段自身为准，不做任何结构改写。040/041 之外的标准
# dex（035-039）不收——那些由 d8 语料覆盖（gen_corpus.sh）。
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${1:-$script_dir/../../build/corpus}"
ADB=${LIBDEX_ADB:-adb}

SERIAL_ARGS=()
if [ -n "${LIBDEX_ART_SERIAL:-}" ]; then
    SERIAL_ARGS=(-s "$LIBDEX_ART_SERIAL")
fi

# git-bash/MSYS 会把 /data/... 这类设备伪路径改写成宿主机路径；adb 的调用
# 统一关闭改写，宿主侧路径由 host_path 预先转成 Windows 形态（非 MSYS 环境
# 两者都是恒等）。
host_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m -- "$1"
    else
        printf '%s' "$1"
    fi
}
adb_run() {
    MSYS_NO_PATHCONV=1 "$ADB" "${SERIAL_ARGS[@]}" "$@"
}

command -v "$ADB" >/dev/null 2>&1 || { echo "error: $ADB not found" >&2; exit 2; }
PY=$(command -v python3 || command -v python) || { echo "error: python3 required" >&2; exit 2; }

adb_run get-state >/dev/null 2>&1 || {
    echo "error: no adb device (set LIBDEX_ART_SERIAL or connect one)" >&2
    exit 2
}

# root 尝试：已在 root 状态的设备上无害；失败不阻断（有的环境本来可读）。
adb_run root >/dev/null 2>&1 || true
adb_run wait-for-device >/dev/null 2>&1 || true

listing=$(adb_run shell \
    "find /data/dalvik-cache /data/app -type f \( -name '*.vdex' -o -name '*.cdex' \) 2>/dev/null" \
    | tr -d '\r' | sort -u | head -n "${LIBDEX_EXTRACT_LIMIT:-16}")
if [ -z "$listing" ]; then
    echo "error: no vdex/cdex visible; /data not readable on this build?" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out_dir"

n=0
while IFS= read -r f; do
    n=$((n + 1))
    safe="$(printf '%s' "$f" | tr -c 'A-Za-z0-9._@-' '_')"
    adb_run pull "$f" "$(host_path "$work")/$safe" >/dev/null
done <<EOF
$listing
EOF
echo "pulled $n candidates"

# 切取与分类统一交给内嵌 python：扫描内嵌 magic，按段自身 header 的
# file_size（偏移 +32 的 u32）定长切出，并校验落在容器边界内。来源清单经
# 临时文件传递——设备伪路径不能经 argv（MSYS 会改写），heredoc 又占着
# stdin；给 python 的路径显式转成 Windows 形态。
printf '%s\n' "$listing" > "$work/sources.txt"
py_sources=$(host_path "$work/sources.txt")
py_work=$(host_path "$work")
py_out=$(host_path "$out_dir")
"$PY" - "$py_sources" "$py_work" "$py_out" <<'PY'
import hashlib
import os
import struct
import sys

sources_file, work, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
with open(sources_file, encoding="utf-8") as fh:
    listing = fh.read()

def magic_kind(buf, off):
    if buf[off:off + 4] != b"dex\n" and buf[off:off + 4] != b"cdex":
        return None
    return buf[off:off + 8].decode("ascii", "replace")

def is_wanted(magic):
    return magic.startswith("dex\n040") or magic.startswith("dex\n041") or \
        magic.startswith("cdex")

written, skipped = [], []
for name in sorted(os.listdir(work)):
    path = os.path.join(work, name)
    with open(path, "rb") as fh:
        buf = fh.read()
    base = os.path.basename(name)
    outer = magic_kind(buf, 0) or ""

    spans = []
    if outer.startswith("dex\n") or outer.startswith("cdex"):
        spans.append(0)                      # 本身就是一段 dex/cdex
    else:                                    # vdex 等容器：扫描内嵌段
        for needle in (b"dex\n0", b"cdex0"):
            at = 0
            while True:
                at = buf.find(needle, at)
                if at < 0:
                    break
                if magic_kind(buf, at):
                    spans.append(at)
                at += 1
        spans = sorted(set(spans))

    for i, off in enumerate(spans, start=1):
        magic = magic_kind(buf, off)
        if not is_wanted(magic):
            skipped.append((base, off, magic))
            continue
        if off + 36 > len(buf):
            skipped.append((base, off, magic + " truncated"))
            continue
        (size,) = struct.unpack_from("<I", buf, off + 32)
        # 标准 dex header 至少 112 字节；cdex 头更小但同样有 file_size 字段。
        floor = 112 if magic.startswith("dex\n") else 64
        if not floor <= size <= len(buf) - off:
            skipped.append((base, off, magic + " bad file_size"))
            continue
        ext = "cdex" if magic.startswith("cdex") else "dex"
        ver = magic[4:8] if ext == "cdex" else magic[4:7]  # cdex0015 / dex 040
        suffix = f"_{i}" if len(spans) > 1 else ""
        tail = "" if base.endswith("." + ext) else "." + ext
        out_name = f"art{ver}_{base}{suffix}{tail}"
        data = buf[off:off + size]
        with open(os.path.join(out_dir, out_name), "wb") as fh:
            fh.write(data)
        written.append((out_name, len(data),
                        hashlib.sha256(data).hexdigest(), base, off, magic))

manifest = os.path.join(out_dir, "manifest_art.sha256")
with open(manifest, "w", newline="\n") as fh:
    for out_name, size, digest, _, _, _ in sorted(written):
        fh.write(f"{digest}  {out_name}\n")

report = os.path.join(out_dir, "extract_art_report.txt")
with open(report, "w", newline="\n") as fh:
    fh.write(f"sources:\n{listing}\n\nwritten:\n")
    for out_name, size, digest, src, off, magic in sorted(written):
        fh.write(f"{out_name}  bytes={size}  magic={magic!r}  "
                 f"from={src}+{off}  sha256={digest}\n")
    fh.write("\nskipped:\n")
    for base, off, why in skipped:
        fh.write(f"{base}+{off}  {why!r}\n")

print(f"extracted {len(written)} section(s), skipped {len(skipped)}; "
      f"manifest: {manifest}")
PY

fingerprint=$(adb_run shell getprop ro.build.fingerprint | tr -d '\r')
sdk=$(adb_run shell getprop ro.build.version.sdk | tr -d '\r')
printf 'device fingerprint=%s sdk=%s\n' "$fingerprint" "$sdk" >> "$out_dir/extract_art_report.txt"

echo "--- report"
cat "$out_dir/extract_art_report.txt"
echo "done: corpus in $out_dir (不入库；提交 manifest_art.sha256 与报告)"
