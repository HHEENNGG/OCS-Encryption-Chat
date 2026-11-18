# Cryptography design and constraints

## Protocol

Use Signal Protocol via a vetted implementation; do not invent a protocol. Evaluate libsignal's current public API, supported usage, release cadence, and license before integration. Public availability of source code does not imply a stable third-party SDK contract.

Expected protocol concepts include identity keys, signed prekeys, one-time prekeys, initial session establishment, and Double Ratchet message processing. Exact algorithms and formats must follow the selected implementation's current specification and API.

## Offline constraint

A serverless deployment cannot assume the normal online prekey directory workflow. The project must implement and review a manual bundle exchange lifecycle. This is a protocol integration project, not merely exporting a public key.

A bundle design must define:
- protocol and bundle format version
- identity public key and fingerprint
- signed prekey and signature
- one-time prekey inventory and unique identifiers
- bundle creation/expiry metadata
- import validation and signature checks
- one-time prekey consumption and duplicate import policy
- replenishment via a new manually transferred bundle
- recovery behavior if a message or state update is lost

Do not reuse one-time prekeys. Do not silently downgrade to static public-key encryption when prekeys run out. Fail closed and require a new verified bundle.

## Identity verification

Show a stable fingerprint derived from identity public key using the protocol's recommended encoding. Both users compare fingerprints out-of-band (in person or by a separately trusted channel). A QR code or file transfer alone does not authenticate the identity.

## Message envelope

The outer envelope should contain only minimal routing/version metadata and opaque protocol ciphertext. Treat every clipboard field as untrusted. Do not include plaintext sender names, message previews, or sensitive metadata unless the user explicitly accepts the leakage.

Example framing (illustrative only; not a Signal wire format):

-----BEGIN OCS ENCRYPTED MESSAGE-----
OCS-Version: 1
Payload: <base64 opaque protocol payload>
-----END OCS ENCRYPTED MESSAGE-----

The protocol adapter must own the actual serialized Signal message format.

## Key derivation and storage

Use Argon2id to derive a wrapping key from the user's master password with a unique random salt and calibrated parameters. Use a random data-encryption key (DEK); wrap the DEK and individual private/session key blobs with an authenticated encryption construction. Never derive the database key directly from a short password without a memory-hard KDF.

Use a separate random key for each purpose where practical. Keep key versioning and rotation metadata.

## Non-goals

- No custom cryptographic primitive.
- No claim that clipboard transport is confidential.
- No claim that a compromised endpoint is protected.
- No delivery/read receipts without an authenticated return message.
