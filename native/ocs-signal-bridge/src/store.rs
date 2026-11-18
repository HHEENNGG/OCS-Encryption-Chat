// In-memory protocol stores for a single bridge call.
// SPDX-License-Identifier: AGPL-3.0-only
//
// The C# layer owns durable persistence: every call receives the current
// serialized state and returns the updated state, which the caller must commit
// transactionally before exposing ciphertext. These stores never touch disk.
//
// Identity trust is FAIL-CLOSED: the remote identity is pinned to the key from
// the imported, user-verified bundle. Any mismatch is rejected; there is no
// trust-on-first-use and no silent identity replacement.

use std::collections::HashMap;

use async_trait::async_trait;
use libsignal_protocol::error::Result;
use libsignal_protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress,
    PublicKey, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore,
};

pub struct IdentityStore {
    pub pair: IdentityKeyPair,
    pub registration_id: u32,
    pub remote_address: ProtocolAddress,
    pub expected_remote: IdentityKey,
    pub known: HashMap<ProtocolAddress, IdentityKey>,
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        if address != &self.remote_address || *identity != self.expected_remote {
            return Err(SignalProtocolError::UntrustedIdentity(address.clone()));
        }
        let change = match self.known.get(address) {
            None => IdentityChange::NewOrUnchanged,
            Some(k) if k == identity => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
        };
        self.known.insert(address.clone(), *identity);
        Ok(change)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool> {
        Ok(address == &self.remote_address && *identity == self.expected_remote)
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        Ok(self.known.get(address).copied())
    }
}

pub struct Sessions {
    pub map: HashMap<ProtocolAddress, SessionRecord>,
}

#[async_trait(?Send)]
impl SessionStore for Sessions {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        Ok(self.map.get(address).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()> {
        self.map.insert(address.clone(), record.clone());
        Ok(())
    }
}

pub struct PreKeys {
    pub map: HashMap<PreKeyId, PreKeyRecord>,
    /// Set by the protocol only after AEAD-verified decryption commits.
    pub consumed: Option<PreKeyId>,
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeys {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        self.map
            .get(&prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.map.insert(prekey_id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        if self.map.remove(&prekey_id).is_some() {
            self.consumed = Some(prekey_id);
        }
        Ok(())
    }
}

pub struct SignedPreKeys {
    pub map: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeys {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord> {
        self.map
            .get(&signed_prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.map.insert(signed_prekey_id, record.clone());
        Ok(())
    }
}

pub struct KyberPreKeys {
    pub map: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
    pub consumed: Option<KyberPreKeyId>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeys {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord> {
        self.map
            .get(&kyber_prekey_id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.map.insert(kyber_prekey_id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<()> {
        self.consumed = Some(kyber_prekey_id);
        Ok(())
    }
}
