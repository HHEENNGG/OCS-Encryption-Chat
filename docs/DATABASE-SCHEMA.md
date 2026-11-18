# Logical database schema (proposal)

All sensitive columns must be encrypted at application layer as well as protected by the encrypted database.

- contacts(id, display_name_enc, identity_fingerprint, trust_state, created_at)
- conversations(id, contact_id, protocol_id, state_blob_enc, created_at, updated_at)
- messages(id, conversation_id, direction, envelope_enc, created_at, local_status)
- identity_material(id, kind, key_blob_enc, key_version, created_at)
- prekey_material(id, key_id, key_blob_enc, consumed_at, key_version)
- exchange_packages(id, peer_id, package_hash, package_version, imported_at, status)
- security_events(id, event_type, details_enc, created_at)
- app_settings(setting_key, value_enc)

Do not store plaintext message previews, plaintext full-text indexes, or secret values in event details.
