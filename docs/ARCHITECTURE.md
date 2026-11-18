# Architecture

## Product boundary

OCS Encryption Chat is a local desktop client. It does not send messages to IM providers and cannot observe whether a user actually pressed Send in another application. A local "copied" status must never be presented as delivered/read.

## Layers

1. Avalonia presentation: views and view models only.
2. Application services: orchestration, validation, lifecycle.
3. Domain/core: contacts, conversations, message state and interfaces.
4. Crypto adapter: Rust FFI boundary; only audited protocol implementation may perform crypto.
5. Storage adapter: SQLCipher-backed repository, key vault, encrypted backup.
6. Platform adapters: clipboard, notifications, OS key protection.

## Dependency rules

- UI -> application interfaces, never native crypto internals.
- Clipboard adapter -> clipboard interface only; it does not decrypt.
- Message coordinator -> crypto interface + encrypted repository.
- Crypto engine -> protocol library; no UI or database dependency.
- Storage -> receives encrypted records and wrapped key material.
- No network client package in production dependency graph.

## Data flow: incoming

Clipboard event -> size/type guard -> strict OCS envelope parser -> conversation hint lookup -> authenticated protocol decrypt -> transactionally persist ciphertext and updated session state -> render plaintext in memory.

Do not persist plaintext message bodies, plaintext search indexes, or plaintext notification previews.

## Data flow: outgoing

User input -> protocol encrypt -> transactionally persist encrypted envelope + updated session state -> clipboard write -> show "Copied; send manually".

The Ratchet state must be committed consistently with the message ciphertext before clipboard exposure. Recovery behavior must be tested under process termination and disk errors.

## Concurrency

Serialize protocol operations per conversation. Two messages for the same session must not mutate Ratchet state concurrently. Different conversations may be processed independently.
