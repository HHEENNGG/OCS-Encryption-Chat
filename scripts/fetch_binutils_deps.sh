#!/usr/bin/env bash
# Provision msys2 mingw64 binutils (dlltool/as) and the DLLs they need, so the
# rustup windows-gnu toolchain can link raw-dylib import libraries (windows-sys).
#
# The rustup "self-contained" dlltool cannot spawn an assembler; msys2 dlltool
# works but needs libintl-8.dll -> libiconv-2.dll, zlib1.dll, libzstd.dll.
# Verified on this repo's build machine with the pinned versions below.
#
# Environment overrides:
#   OCS_TOOLS_DIR  install root (default: $HOME/AppData/Local/Temp/ocs-setup)
#   MSYS2_MIRROR   package mirror (default: USTC)
set -euo pipefail

HOME_UNIX="${HOME:-$(cd "$USERPROFILE" && pwd)}"
OCS_TOOLS_DIR="${OCS_TOOLS_DIR:-$HOME_UNIX/AppData/Local/Temp/ocs-setup}"
M="${MSYS2_MIRROR:-https://mirrors.ustc.edu.cn/msys2/mingw/mingw64}"
mkdir -p "$OCS_TOOLS_DIR/mingw64"
cd "$OCS_TOOLS_DIR"

fetch() { # fetch <package-file>
  echo "== $1"
  curl -sfL -m 180 --retry 3 -o dep.pkg.tar.zst "$M/$1"
  tar --zstd -xf dep.pkg.tar.zst -C mingw64
  rm -f dep.pkg.tar.zst
}

# Pinned, verified versions (mirror directory indexes are truncated, so do not
# rely on scraping the latest version for every package).
fetch mingw-w64-x86_64-binutils-2.47-4-any.pkg.tar.zst
fetch mingw-w64-x86_64-gettext-runtime-1.0-1-any.pkg.tar.zst
fetch mingw-w64-x86_64-zlib-1.3.2-2-any.pkg.tar.zst
fetch mingw-w64-x86_64-zstd-1.5.7-2-any.pkg.tar.zst
fetch mingw-w64-x86_64-libiconv-1.18-1-any.pkg.tar.zst

export PATH="$OCS_TOOLS_DIR/mingw64/mingw64/bin:$PATH"
mkdir -p dlltest && cd dlltest
printf 'LIBRARY bcryptprimitives.dll\nEXPORTS\nProcessPrng\n' > t.def
dlltool.exe -d t.def -D bcryptprimitives.dll -l t3.lib -m i386:x86-64 -f --64 --no-leading-underscore --temp-prefix bcryptprimitives.dll
echo "dlltool-exit=$?"
ls -la t3.lib
echo "BINUTILS_READY"