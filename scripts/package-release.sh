#!/usr/bin/env bash
# Build one release binary and pack a runtime-only zip into dist/.
#
# Usage:
#   scripts/package-release.sh <rust-target> <zip-name>
#
# The zip contains the binary, proxybridge.toml, and README-run.txt.
# Windows zips also try to add unmodified WinDivert 2.2.2 x64 runtime files
# (LGPL-3.0 or GPL-2.0). If that download fails, NOTICE.txt says where to get them.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <rust-target> <zip-name>" >&2
  exit 2
fi

TARGET="$1"
ZIP_NAME="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  PY=python
fi

write_windivert_notice() {
  local dest="$1"
  local mode="$2"
  if [[ "$mode" == included ]]; then
    cat > "${dest}/NOTICE.txt" <<'EOF'
WinDivert 2.2.2 x64 is included unmodified: WinDivert.dll and WinDivert64.sys.
WinDivert is dual-licensed under the GNU LGPL version 3 or the GNU GPL version 2.
The license text is LICENSE-WinDivert.txt. Source:
https://github.com/basil00/WinDivert

ProxyBridge loads WinDivert.dll at runtime for --mode windivert. It is not
statically linked. Run that mode from an elevated (Administrator) prompt.
--mode socks does not use these files.
EOF
  else
    cat > "${dest}/NOTICE.txt" <<'EOF'
WinDivert.dll and WinDivert64.sys are not in this zip.
They are required only for: proxybridge.exe run --mode windivert

Download WinDivert 2.2.2 and place the x64 WinDivert.dll and WinDivert64.sys
next to proxybridge.exe:
https://github.com/basil00/WinDivert/releases

WinDivert is dual-licensed LGPL-3.0 or GPL-2.0. --mode socks does not need it.
EOF
  fi
}

fetch_windivert() {
  local dest="$1"
  local ver="${WINDIVERT_VERSION:-2.2.2}"
  local tmp zip
  tmp="$(mktemp -d)"
  zip="${tmp}/WinDivert.zip"
  if ! curl -fsSL --retry 3 -o "$zip" \
      "https://github.com/basil00/WinDivert/releases/download/v${ver}/WinDivert-${ver}-A.zip"; then
    write_windivert_notice "$dest" missing
    rm -rf "$tmp"
    return 0
  fi
  if ! "$PY" - "$zip" "$dest" "$ver" <<'PY'
import sys, zipfile
src, dest, ver = sys.argv[1], sys.argv[2], sys.argv[3]
prefix = f"WinDivert-{ver}-A/x64/"
wanted = {
    prefix + "WinDivert.dll": "WinDivert.dll",
    prefix + "WinDivert64.sys": "WinDivert64.sys",
    f"WinDivert-{ver}-A/LICENSE": "LICENSE-WinDivert.txt",
}
with zipfile.ZipFile(src) as zf:
    names = set(zf.namelist())
    for src_name, out_name in wanted.items():
        if src_name not in names:
            raise SystemExit(f"missing {src_name}")
        with zf.open(src_name) as inp, open(dest + "/" + out_name, "wb") as out:
            out.write(inp.read())
PY
  then
    rm -f "${dest}/WinDivert.dll" "${dest}/WinDivert64.sys" "${dest}/LICENSE-WinDivert.txt"
    write_windivert_notice "$dest" missing
    rm -rf "$tmp"
    return 0
  fi
  write_windivert_notice "$dest" included
  rm -rf "$tmp"
}

case "$TARGET" in
  *windows*) BIN_NAME="proxybridge.exe" ;;
  *) BIN_NAME="proxybridge" ;;
esac

case "$TARGET" in
  aarch64-unknown-linux-gnu)
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
    ;;
  x86_64-pc-windows-gnu)
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}"
    ;;
esac

if ! rustup target list --installed | grep -qx "$TARGET"; then
  rustup target add "$TARGET"
fi

echo "==> cargo build --release -p proxybridge-cli --target ${TARGET}"
cargo build --release -p proxybridge-cli --target "$TARGET"

BIN_SRC="target/${TARGET}/release/${BIN_NAME}"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "missing binary: ${BIN_SRC}" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

cp "$BIN_SRC" "${STAGE}/${BIN_NAME}"
case "$TARGET" in
  aarch64-unknown-linux-gnu)
    command -v aarch64-linux-gnu-strip >/dev/null && aarch64-linux-gnu-strip "${STAGE}/${BIN_NAME}" || true
    ;;
  x86_64-pc-windows-gnu)
    command -v x86_64-w64-mingw32-strip >/dev/null && x86_64-w64-mingw32-strip "${STAGE}/${BIN_NAME}" || true
    ;;
  *apple*|*windows*) ;;
  *) command -v strip >/dev/null && strip "${STAGE}/${BIN_NAME}" || true ;;
esac
chmod +x "${STAGE}/${BIN_NAME}" 2>/dev/null || true

if [[ -f profiles/user-proxifier-profile.toml ]]; then
  cp profiles/user-proxifier-profile.toml "${STAGE}/proxybridge.toml"
else
  cp proxybridge.toml "${STAGE}/proxybridge.toml"
fi
if [[ -d profiles ]]; then
  mkdir -p "${STAGE}/profiles"
  find profiles -maxdepth 1 -type f \( -name '*.ppx' -o -name '*.toml' \) -exec cp {} "${STAGE}/profiles/" \;
fi

if [[ "$TARGET" == *windows* ]]; then
  RUN_BIN="proxybridge.exe"
else
  RUN_BIN="./proxybridge"
fi

cat > "${STAGE}/README-run.txt" <<EOF
ProxyBridge runtime (${ZIP_NAME})

Default upstream is SOCKS5 at 127.0.0.1:7898.
proxybridge.toml is the Proxifier profile (Direct by default, proxy for the
Dev/AI/Game domain lists, UDP left direct). The original .ppx and the same
toml are in profiles/. Start from this directory so ./proxybridge.toml loads.
CLI flags and PROXYBRIDGE_PROXY_* override the file.
You can also pass the original profile:
  ${RUN_BIN} config --config profiles/user-proxifier-profile.ppx

  ${RUN_BIN} run --mode socks
  ${RUN_BIN} config
  ${RUN_BIN} backends

Linux transparent TCP and UDP (root):
  sudo ${RUN_BIN} run --mode redirect

Windows transparent IPv4 (--mode windivert) needs WinDivert.dll and
WinDivert64.sys next to proxybridge.exe, and an elevated prompt.
macOS transparent capture needs a signed Network Extension, which is not
in this zip. Use --mode socks on macOS.
EOF

if [[ "$TARGET" == *windows* ]]; then
  fetch_windivert "${STAGE}"
fi

mkdir -p dist
OUT="dist/${ZIP_NAME}.zip"
rm -f "$OUT"
"$PY" - "$STAGE" "$ROOT/$OUT" <<'PY'
import os, sys, zipfile
stage, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for dirpath, _, files in os.walk(stage):
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            arc = os.path.relpath(path, stage).replace(os.sep, "/")
            zf.write(path, arc)
print(dest)
PY

echo "==> ${OUT}"
"$PY" - "$ROOT/$OUT" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    for info in zf.infolist():
        print(f"{info.file_size:10}  {info.filename}")
PY
