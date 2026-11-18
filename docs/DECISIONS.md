# Architecture Decision Records

## ADR-001: Avalonia for UI
Decision: Avalonia for shared desktop UI.
Reason: one C#/XAML codebase for Windows, Linux and macOS; platform APIs remain behind adapters.
Status: accepted, subject to platform support matrix.

## ADR-002: Rust crypto boundary
Decision: isolate protocol implementation behind a Rust library and narrow FFI.
Reason: isolate sensitive code and avoid leaking protocol internals into UI.
Status: implemented. Library choice: official signalapp/libsignal v0.108.0
(vendored, AGPL-3.0-only), PQXDH + Double Ratchet, exposed through a single
JSON-over-C-ABI entry point (`ocs_call`) with catch_unwind, bounded inputs and
no key material in logs. Rust tests 8/8, C# tests 29/29, headless selftest 21/21.
Independent FFI/security audit remains an M5 release blocker; the bridge is
functional but NOT audited for real sensitive communication.

## ADR-003: No server
Decision: no account server, message relay, push service or remote key directory.
Consequence: key bundles, prekey replenishment and all message transport are manual through user-controlled channels.

## ADR-004: Fail closed storage
Decision: no plaintext database fallback.
Consequence: app cannot enable persistent chat until encrypted storage is initialized successfully.
