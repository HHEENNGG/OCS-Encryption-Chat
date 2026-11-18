# Acceptance test matrix

| Area | Test | Expected result |
|---|---|---|
| Offline | Run with network blocked | Core local UI and cryptographic workflow have no network dependency |
| Identity | Import tampered bundle | Reject |
| Identity | Fingerprint mismatch | Never mark verified |
| Prekeys | Reuse consumed one-time prekey | Reject or protocol-defined safe behavior |
| Messages | Replay same envelope | No duplicate display or state corruption |
| Storage | Inspect DB/WAL/logs | No plaintext message or private key |
| Password | Wrong master password | Fail closed |
| Backup | Corrupt archive | Reject without altering active DB |
| Clipboard | Oversized/malformed text | Ignore safely |
| Clipboard | Own ciphertext copied | No recursive import |
| Concurrency | Two messages same session | Serialized protocol state updates |
| Recovery | Kill process during commit | Recover to a consistent state |
| Platform | X11 / Wayland / macOS / Windows | Documented clipboard behavior and permission prompts |

Cryptographic tests must use test vectors from the selected protocol implementation. Do not create homemade vectors and treat them as proof.
