#!/usr/bin/env bash
# Build + test the OCS Rust crypto bridge in an ASCII path.
#
# Verified toolchain (this repo's prebuilt DLL was produced with it):
#   - rustup stable-x86_64-pc-windows-gnu (rustc 1.100.0), bundled ld
#   - protoc 29.3 (prost-build requirement)
#   - msys2 mingw64 binutils 2.47 (dlltool/as) + libintl-8/libiconv-2/zlib1/libzstd DLLs
#     (see fetch_binutils_deps.sh)
#
# Environment overrides:
#   OCS_NATIVE_DIR  ASCII build tree synced by copy_native.py (default: $HOME/ocs-native)
#   OCS_TOOLS_DIR   protoc + mingw64 location (default: $HOME/AppData/Local/Temp/ocs-setup)
#   PROTOC          explicit protoc.exe path
#   OCS_REPO_NATIVE repo native/ dir; when set, the built DLL is copied to
#                   $OCS_REPO_NATIVE/prebuilt/win-x64/ocs_signal_bridge.dll
set -eo pipefail

HOME_UNIX="${HOME:-$(cd "$USERPROFILE" && pwd)}"
OCS_NATIVE_DIR="${OCS_NATIVE_DIR:-$HOME_UNIX/ocs-native}"
OCS_TOOLS_DIR="${OCS_TOOLS_DIR:-$HOME_UNIX/AppData/Local/Temp/ocs-setup}"

export PATH="$HOME_UNIX/.cargo/bin:$OCS_TOOLS_DIR/mingw64/mingw64/bin:$PATH"
export PROTOC="${PROTOC:-$OCS_TOOLS_DIR/protoc/bin/protoc.exe}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true   # spqr is a git dependency

cd "$OCS_NATIVE_DIR/ocs-signal-bridge"
echo "=== cargo build --release ==="
cargo build --release
echo "=== cargo test --release ==="
cargo test --release
echo "=== BUILD+TEST DONE ==="
ls -la target/release/ocs_signal_bridge.dll

if [ -n "${OCS_REPO_NATIVE:-}" ]; then
  mkdir -p "$OCS_REPO_NATIVE/prebuilt/win-x64"
  cp target/release/ocs_signal_bridge.dll "$OCS_REPO_NATIVE/prebuilt/win-x64/ocs_signal_bridge.dll"
  cp Cargo.lock "$OCS_REPO_NATIVE/ocs-signal-bridge/Cargo.lock"
  echo "DLL + Cargo.lock copied back to repo"
fi