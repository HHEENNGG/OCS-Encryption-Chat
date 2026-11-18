# Roadmap

## Milestone 0 — Buildable shell
- Avalonia shell and navigation
- dependency boundaries
- CI builds on Windows/Linux/macOS
- no crypto claims

## Milestone 1 — Crypto feasibility spike (release blocker)
- choose and review Signal implementation
- validate API, license and distribution terms
- establish two-device interoperability
- design manual offline prekey bundle lifecycle
- test prekey consumption, replenishment and recovery
- protocol review before integration

## Milestone 2 — Encrypted persistence
- SQLCipher integration
- Argon2id key wrapping
- platform key protectors
- encrypted backup and restore
- filesystem plaintext audit

## Milestone 3 — Clipboard workflow
- platform-specific clipboard adapters
- strict envelope parser
- deduplication and own-write suppression
- incoming decrypt and archive
- outgoing encrypt and copy

## Milestone 4 — Multi-session UI
- contacts and conversations
- identity verification screen
- message history and search strategy that does not leak plaintext
- security center and lock screen

## Milestone 5 — Release readiness
- cross-platform integration tests
- network isolation test
- dependency and license inventory
- independent security audit
- signed installers and update policy
