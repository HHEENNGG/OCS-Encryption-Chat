# Scripts

Reviewed build and provisioning scripts. All were used to produce the verified
`native/prebuilt/win-x64/ocs_signal_bridge.dll` shipped with this repository.
Paths are parameterized via environment variables; defaults match the original
build machine layout (`%USERPROFILE%`).

Never place secrets, private keys, signing credentials or passwords in scripts
or CI variables without an approved secret-management process.

## Application build (no Rust toolchain needed)

The prebuilt bridge DLL is committed, so the app builds with only the .NET SDK:

```bash
dotnet build OCS-Encryption-Chat.sln -c Release
dotnet run --project src/OCS.App -c Release            # GUI
dotnet run --project src/OCS.App -c Release -- --selftest   # headless E2E matrix
dotnet test tests/OCS.Tests/OCS.Tests.csproj -c Release
```

## Rebuilding the Rust bridge (Windows, GNU toolchain)

Prerequisites: rustup `stable-x86_64-pc-windows-gnu`, protoc (≥ 29), Python 3,
msys2-compatible `tar` with zstd support, Git (for the spqr git dependency).

```bash
# 1. Provision dlltool/as + required DLLs (one-time; see script header).
bash scripts/fetch_binutils_deps.sh

# 2. Sync native/ to an ASCII path — GNU ld cannot link under non-ASCII
#    (e.g. Chinese) workspace paths.
python scripts/copy_native.py

# 3. Build + test, then copy DLL and Cargo.lock back into the repo.
OCS_REPO_NATIVE="$(pwd)/OCS-Encryption-Chat/native" bash scripts/build_bridge.sh
```

`build_bridge.sh` honors `OCS_NATIVE_DIR`, `OCS_TOOLS_DIR`, `PROTOC`.
The bridge depends on the vendored official `libsignal` v0.108.0 sources in
`native/vendor/` (AGPL-3.0-only) plus crates.io/git dependencies pinned in
`native/ocs-signal-bridge/Cargo.lock`.

## .NET SDK provisioning (slow-network helper)

```bash
bash scripts/download_sdk_parallel.sh   # SDK_VERSION / DOTNET_DIR overridable
```

## Diagnostics

- `pe_imports.py <exe-or-dll>` — list a PE file's imported DLLs (used to find
  the missing msys2 dlltool dependencies).