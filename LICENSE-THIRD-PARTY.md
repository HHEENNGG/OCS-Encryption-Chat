# Third-party notices

Last verified: 2026-11-17. Exact resolved versions are pinned in
`native/ocs-signal-bridge/Cargo.lock` (Rust) and the per-project
`packages.lock.json` files (NuGet). Re-verify this inventory before every release.

## License implication for the combined work

The application links the official Signal protocol implementation
(`libsignal`), which is licensed **AGPL-3.0-only**. The combined work
(application + native bridge + vendored libsignal) must therefore be
distributed under AGPL-3.0-compatible terms. A copy of the AGPL-3.0 is
included as `LICENSE` at the repository root. Source code for the exact
build must be made available to recipients as required by the AGPL.

## Cryptographic / protocol components (Rust, native bridge)

| Component | Version / source | License | Role |
|---|---|---|---|
| libsignal (signalapp/libsignal) | tag `v0.108.0`, commit `8be00c282001caa3585d18de0f044c6d500348ab`, vendored at `native/vendor/libsignal-0.108.0/` | AGPL-3.0-only | PQXDH session establishment + Double Ratchet (libsignal-protocol, libsignal-core, signal-crypto) |
| spqr (signalapp/SparsePostQuantumRatchet) | tag `v1.7.0`, commit `3a69df8f01179fce970693f072b710a8ab8dc6c2` (cargo git dependency) | AGPL-3.0 | Sparse post-quantum ratchet extension used by libsignal |
| libcrux-ml-kem | 0.0.10 (crates.io) | Apache-2.0 | ML-KEM/Kyber1024 key encapsulation (formally-verified implementation) |
| curve25519-dalek | 5.0.0 | BSD-3-Clause | Curve25519 group arithmetic |
| x25519-dalek | 3.0.0 | BSD-3-Clause | X25519 key agreement |
| argon2 (RustCrypto) | 0.5.3 | MIT OR Apache-2.0 | Argon2id master-password KDF |
| chacha20poly1305 (RustCrypto) | 0.11.0 | Apache-2.0 OR MIT | XChaCha20-Poly1305 AEAD (vault wrapping, column encryption, backups) |
| sha2 (RustCrypto) | 0.11.1 | MIT OR Apache-2.0 | SHA-256 fingerprints / envelope hashing |
| hkdf / hmac (RustCrypto) | 0.13.0 / 0.13.0 | MIT OR Apache-2.0 | Ratchet KDF chain (inside libsignal) |
| aes / cbc / ctr / ghash (RustCrypto) | 0.9.4 / 0.2.1 / 0.10.1 / 0.6.0 | MIT OR Apache-2.0 | Signal message encryption primitives (inside signal-crypto) |
| hpke-rs | 0.7.0 | MPL-2.0 | HPKE (inside signal-crypto) |
| password-hash / subtle / zeroize (RustCrypto) | 0.5.0 / 2.6.1 / 1.9.1 | MIT OR Apache-2.0 | Password hashing traits, constant-time ops, secret zeroization |
| rand / rand_core | 0.10.4 / 0.10.1 | MIT OR Apache-2.0 | CSPRNG (OS entropy) |
| prost | 0.14.6 | Apache-2.0 | Protocol Buffers wire format (libsignal records) |

Support crates (serde 1.0.229, serde_json 1.0.154, base64 0.22.1, hex 0.4.3,
async-trait 0.1.92, futures-executor 0.3.34 and their transitive dependencies)
are MIT OR Apache-2.0 unless noted in `Cargo.lock` metadata. Full transitive
inventory: `native/ocs-signal-bridge/Cargo.lock`.

## Application components (NuGet)

| Package | Version | License | Role |
|---|---|---|---|
| Avalonia / Avalonia.Desktop / Avalonia.Themes.Fluent / Avalonia.Fonts.Inter | 11.3.23 | MIT | Cross-platform UI framework |
| Microsoft.Data.Sqlite.Core | 10.0.15 | MIT | ADO.NET provider over SQLitePCLRaw |
| SQLitePCLRaw.bundle_e_sqlcipher | 2.1.11 | Apache-2.0 (bundle); SQLCipher community edition BSD-3-Clause | Encrypted SQLite engine (SQLCipher) — no plaintext SQLite fallback |
| xunit / xunit.runner.visualstudio | 2.9.3 / 3.1.5 | Apache-2.0 | Test framework (test project only) |
| Microsoft.NET.Test.Sdk | 17.14.2 | MIT | Test host (test project only) |

## Build-time tools (not redistributed)

- Rust stable 1.100.0 (windows-gnu host target), rustup — MIT/Apache-2.0.
- protoc 29.3 (protobuf code generation for prost-build) — BSD-3-Clause.
- .NET SDK 10.0.404 — MIT.
- MSYS2 mingw-w64 binutils 2.47 (dlltool/as for import libraries) — GPL (build tool only, not linked into the product).

## Security advisory status

No automated advisory audit (e.g. `cargo audit` / NuGet vulnerability scan)
has been run yet. **This is a release blocker (roadmap M5)**: run an advisory
scan against the pinned lock files and record results here before shipping.

## Review status

- libsignal is the official Signal implementation (vetted upstream), integrated
  as vendored source at a pinned tag. Its offline prekey semantics (one-time
  prekey consumption, signed/kyber prekey rotation, fail-closed identity
  pinning) are exercised by `native/ocs-signal-bridge/tests/protocol_flow.rs`
  and `tests/OCS.Tests/ProtocolFlowTests.cs`.
- **No independent security audit of this application has been performed.**
  Do not use it for real sensitive communication until one has (README).