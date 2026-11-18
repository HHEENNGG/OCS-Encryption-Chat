# Security requirements and threat model

## Protect against

- Lost or stolen powered-off device (master password + encrypted storage).
- Accidental plaintext writes to database/logs/backups.
- Clipboard noise and malformed clipboard payloads.
- Message replay and duplicate import.
- Identity key substitution, if fingerprints are verified out-of-band.
- Partial writes and crash-induced protocol state divergence.

## Not fully protected against

- Malware, keyloggers, screen capture or administrator/root compromise on an unlocked endpoint.
- A malicious or compromised IM application that can read clipboard content.
- The IM provider observing message timing, ciphertext size, account identities and other metadata.
- A recipient copying or photographing decrypted content.
- Physical coercion or insecure OS backups.

## Clipboard rules

- Monitor only text formats needed by the app.
- Never store arbitrary clipboard history.
- Ignore own writes using an in-memory nonce/hash window.
- Bound maximum payload size.
- Never auto-execute or interpret clipboard content as commands.
- Offer pause, per-app exclusion where technically supported, and clear status.
- Do not clear clipboard automatically without an explicit user setting; clearing can destroy user data.

## Memory and UI

- Plaintext must exist in memory to display it. Minimize lifetime and copies.
- Avoid plaintext notification previews and logs.
- Lock on inactivity and clear sensitive view models on lock.
- Do not claim secure memory erasure in managed runtimes unless specifically verified.

## Release gates

No production release until:
- protocol implementation reviewed
- offline bundle lifecycle reviewed
- storage and backup audit passed
- platform clipboard permissions tested
- reproducible build and dependency/license inventory produced
- independent security review completed
