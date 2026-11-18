# Encrypted storage

## Requirements

- SQLCipher or another independently audited encrypted database implementation.
- No plaintext SQLite fallback.
- App-layer AEAD encryption for message bodies before repository writes.
- Private identity keys, prekeys and ratchet state stored as wrapped encrypted blobs.
- Master password processed with Argon2id; never stored.
- Database key randomly generated and wrapped by a key-encryption key.
- Platform key store may protect a wrapped key for convenience, but should not silently bypass the master password policy.

## Filesystem audit

Inspect the main DB, WAL, SHM, journal, temporary files, backups, crash dumps, logs, search indexes and OS notification history. A database encryption setting alone does not prove that all copies are encrypted.

## Transaction invariant

For each protocol message, persist the encrypted message and the matching updated protocol state in one transaction or a recoverable journaled operation. Never expose ciphertext for sending if the local protocol state has not been durably committed.

## Backup

Backup should be an authenticated encrypted archive containing:
- encrypted database snapshot
- wrapped identity and session state
- schema version
- crypto/protocol implementation version
- backup format version
- integrity metadata

Restore into a temporary location, validate fully, then atomically replace active data. A backup is not a substitute for re-verifying peer identity after device migration.
