# Build and development

All commands below were executed and verified on the reference build machine
(Windows 11 x64, MSYS2 bash). Versions are pinned; lock files are committed.

## Verified toolchain

| Component | Version | Location / notes |
|---|---|---|
| .NET SDK | 10.0.404 | `C:\Users\63457\.dotnet` (installed via `scripts/download_sdk_parallel.sh`) |
| Rust | stable 1.100.0, host `x86_64-pc-windows-gnu` | rustup; bundled `ld` used for linking |
| protoc | 29.3 (win64) | required by `prost-build`; set `PROTOC` |
| msys2 binutils | 2.47 (`dlltool`/`as`) + `libintl-8`/`libiconv-2`/`zlib1`/`libzstd` DLLs | `scripts/fetch_binutils_deps.sh`; needed for `windows-sys` raw-dylib import libs |
| Git | 2.56 | spqr git dependency (`CARGO_NET_GIT_FETCH_WITH_CLI=true`) |
| NuGet | nuget.org (mirrored via nuget.azure.cn on this machine) | `packages.lock.json` committed for all 5 projects |

Pinned package versions: Avalonia 11.3.23 (Desktop/Themes.Fluent/Fonts.Inter),
Microsoft.Data.Sqlite.Core 10.0.15, SQLitePCLRaw.bundle_e_sqlcipher 2.1.11,
xunit 2.9.3, xunit.runner.visualstudio 3.1.5, Microsoft.NET.Test.Sdk 17.14.2.
Rust dependencies are pinned in `native/ocs-signal-bridge/Cargo.lock`; the
official libsignal v0.108.0 sources are vendored under `native/vendor/`.

## Application build (prebuilt bridge DLL committed)

```bash
export DOTNET_ROOT="$HOME/.dotnet"        # if the SDK is not on PATH
export PATH="$DOTNET_ROOT:$PATH"
dotnet build OCS-Encryption-Chat.sln -c Release
dotnet run --project src/OCS.App -c Release                  # desktop GUI
dotnet run --project src/OCS.App -c Release -- --selftest    # headless E2E matrix
dotnet test tests/OCS.Tests/OCS.Tests.csproj -c Release      # 29 tests
```

`src/OCS.App` and `tests/OCS.Tests` copy `native/prebuilt/win-x64/ocs_signal_bridge.dll`
to their output directories. The app refuses to start if the bridge reports
not-ready (fail closed).

## Rebuilding the Rust bridge

**Windows non-ASCII path caveat:** GNU `ld` cannot open output files under
non-ASCII (e.g. Chinese) paths. Build in an ASCII directory:

```bash
bash scripts/fetch_binutils_deps.sh          # one-time toolchain provisioning
python scripts/copy_native.py                # native/ -> %USERPROFILE%/ocs-native
OCS_REPO_NATIVE="$(pwd)/native" bash scripts/build_bridge.sh
```

`build_bridge.sh` runs `cargo build --release` and `cargo test --release`
(8 tests: PQXDH lifecycle, tampered bundles, OTPK reuse, wrong identity,
tampered ciphertext, KDF/AEAD, fingerprints), then copies the DLL and
`Cargo.lock` back into the repository when `OCS_REPO_NATIVE` is set.

Environment overrides: `OCS_NATIVE_DIR`, `OCS_TOOLS_DIR`, `PROTOC`.
On Linux/macOS the bridge builds directly in-tree with a normal Rust toolchain
(`cd native/ocs-signal-bridge && cargo test --locked && cargo build --release`);
platform-specific prebuilt DLLs for those RIDs are not yet committed.

## Offline build preparation

A developer workstation may connect to retrieve dependencies. To build later
without network:
1. Pin every .NET NuGet and Cargo dependency (done: lock files committed).
2. Populate the NuGet package cache and Cargo registry/git cache on a
   connected build machine (the vendored libsignal tree removes the largest
   git dependency; spqr still needs a cached git checkout).
3. Verify package hashes and licenses (see `LICENSE-THIRD-PARTY.md`).
4. Build with network disabled.
5. Test the installed application with outbound network blocked.

Do not claim "offline build" merely because the running app has no network
feature. The production dependency graph contains no network client packages.

## Publish examples

```bash
dotnet publish src/OCS.App/OCS.App.csproj -c Release -r win-x64
dotnet publish src/OCS.App/OCS.App.csproj -c Release -r linux-x64
dotnet publish src/OCS.App/OCS.App.csproj -c Release -r osx-arm64
```

Only `win-x64` has a committed prebuilt bridge DLL. Linux/macOS publishes
require building the bridge for those targets first and placing the shared
library next to the app output. Release signing, independent audit and
cross-platform clipboard verification remain M5 release blockers (see
`docs/ROADMAP.md`).