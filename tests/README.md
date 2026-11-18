# Test plan

## Implemented automated coverage

- `tests/OCS.Tests` (xunit, 29 tests): bridge primitives (RNG/KDF/AEAD/identity),
  strict clipboard envelope parser (oversized, malformed, unknown headers,
  bad base64, wrong version, path-traversal hints), protocol flows (two-vault
  PQXDH interoperability, OTPK consumption, replay rejection, self-write
  suppression, tampered ciphertext/bundle rejection, fingerprint mismatch
  never Verified, concurrent sends serialized, restart persistence), storage
  security (wrong password fail closed, no plaintext at rest incl. backups,
  corrupted backup rejected without touching active data, backup roundtrip).
- `native/ocs-signal-bridge` (cargo test, 8 tests): full Alice/Bob lifecycle,
  tampered bundles, consumed-OTPK reuse, wrong remote identity, tampered
  ciphertext, KDF/AEAD vectors, fingerprint stability and input limits.
- `dotnet run --project src/OCS.App -- --selftest` (21 checks): headless
  two-endpoint matrix over the real service stack, including restore into a
  fresh directory and byte-scans of DB/vault/backup for plaintext.
- GUI smoke on Windows via UIAutomation: unlock, vault creation and all six
  pages render and operate.

Run everything:

```bash
dotnet test tests/OCS.Tests/OCS.Tests.csproj -c Release
dotnet run --project src/OCS.App -c Release -- --selftest
# Rust (see scripts/README.md for the Windows ASCII-path build):
cd native/ocs-signal-bridge && cargo test --locked
```

## Still required before release (M5)

- Protocol known-answer vectors from the selected, audited Signal implementation.
- Alice/Bob interoperability across Windows, Linux, and macOS (only Windows verified).
- Crash/restart between each persistence boundary (kill -9 matrix).
- WAL/SHM/journal/crash-dump/log/index/notification-history plaintext audit
  beyond the current DB/vault/backup byte scans.
- Offline network test: application makes no outbound connections (dependency
  graph contains no network client; runtime verification still required).
- Clipboard permission behavior under X11 and Wayland.
- Independent cryptographic/FFI audit; signed installers.