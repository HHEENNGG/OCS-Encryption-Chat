# Manual offline key exchange

## Goal

Establish a session between two devices without a key directory or server.

## Required user journey

1. Alice creates an identity and a signed prekey bundle locally.
2. Alice exports a public-only bundle (QR or file). Secret key material must never be exported in a public bundle.
3. Bob imports it and validates its format, signatures, version and expiry.
4. Bob creates his corresponding public bundle and returns it to Alice.
5. Both users compare identity fingerprints through a separately trusted channel.
6. The protocol adapter establishes the initial session according to the selected Signal implementation.
7. The app records the verified identity and bundle version.

## One-time prekeys

One-time prekeys require a lifecycle. A bundle can include a finite pool. The recipient must atomically mark a one-time prekey consumed when it is used. The sender must not assume it can reuse a consumed prekey. Replenishment requires a newly generated and manually transferred bundle.

## Important limitation

If both users exchange a single static public key and then encrypt messages with a static shared key, that is not an equivalent implementation of Signal Protocol and does not provide the same forward-secrecy properties. Do not use such a fallback.

## QR and file exchange

- QR should carry only public bundle material and be size-limited.
- File bundles should be versioned and integrity-checked.
- Fingerprint comparison is mandatory before showing "Verified".
- Import must be atomic; malformed bundles must not partially alter a session.
- Private identity keys and local ratchet state must never be included in public exchange files.
