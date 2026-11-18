// Bridge operations: JSON request -> JSON response, binary fields as base64.
// SPDX-License-Identifier: AGPL-3.0-only
//
// All Signal Protocol work is delegated to the vendored official libsignal.
// This module only (de)serializes state, enforces input limits, and pins the
// remote identity. It implements no cryptography of its own.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use futures_executor::block_on;
use libsignal_protocol::{
    kem, CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignalMessage,
    SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use crate::store::{IdentityStore, KyberPreKeys, PreKeys, Sessions, SignedPreKeys};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub const PROTOCOL_NAME: &str = "signal-pqxdh";
pub const BUNDLE_FORMAT_VERSION: u32 = 1;
const MAX_OTPK_EXPORT: u32 = 200;
const MAX_OTPK_IMPORT: usize = 1000;
const MAX_PLAINTEXT: usize = 1_000_000;
const MAX_AEAD_PLAINTEXT: usize = 16 * 1024 * 1024;

// ── small helpers ────────────────────────────────────────────────────────────

fn b64e(b: &[u8]) -> String {
    B64.encode(b)
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|_| "invalid base64".to_string())
}

fn req_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field '{k}'"))
}

fn req_u32(v: &Value, k: &str) -> Result<u32, String> {
    v.get(k)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("missing/invalid integer field '{k}'"))
}

fn opt_u32(v: &Value, k: &str, default: u32) -> Result<u32, String> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(default),
        Some(_) => req_u32(v, k),
    }
}

fn req_bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    b64d(req_str(v, k)?)
}

fn opt_bytes(v: &Value, k: &str) -> Result<Option<Vec<u8>>, String> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(b64d(s)?)),
        _ => Err(format!("field '{k}' must be base64 string or null")),
    }
}

fn addr(v: &Value, name_key: &str, device_key: &str) -> Result<ProtocolAddress, String> {
    let name = req_str(v, name_key)?;
    if name.is_empty() || name.len() > 256 {
        return Err(format!("invalid address name '{name_key}'"));
    }
    let device = opt_u32(v, device_key, 1)?;
    if device == 0 || device > 127 {
        return Err("deviceId must be 1..=127".to_string());
    }
    let device_id = DeviceId::new(device as u8).map_err(|_| "invalid deviceId".to_string())?;
    Ok(ProtocolAddress::new(name.to_string(), device_id))
}

fn identity_pair(v: &Value) -> Result<IdentityKeyPair, String> {
    let bytes = req_bytes(v, "identityKeyPair")?;
    IdentityKeyPair::try_from(bytes.as_slice()).map_err(|e| format!("identityKeyPair: {e}"))
}

fn fingerprint_of(pk: &PublicKey) -> String {
    let digest = sha2::Sha256::digest(pk.serialize());
    let hex = hex::encode_upper(digest);
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Howard Hinnant's civil-calendar algorithms (public domain), UTC only.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn format_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn parse_utc(s: &str) -> Result<u64, String> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(format!("invalid UTC timestamp '{s}' (want YYYY-MM-DDTHH:MM:SSZ)"));
    }
    let num = |r: std::ops::Range<usize>| -> Result<i64, String> {
        s[r].parse::<i64>().map_err(|_| format!("invalid timestamp '{s}'"))
    };
    let (y, mo, d, h, mi, sec) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || sec > 59
    {
        return Err(format!("timestamp out of range '{s}'"));
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    if days < 0 {
        return Err(format!("timestamp before epoch '{s}'"));
    }
    Ok(days as u64 * 86400 + h as u64 * 3600 + mi as u64 * 60 + sec as u64)
}

// ── bundle format ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPart {
    pub id: u32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OtpkPart {
    pub id: u32,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub protocol: String,
    pub format_version: u32,
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_public_key: String,
    pub fingerprint: String,
    pub signed_pre_key: SignedPart,
    pub kyber_pre_key: SignedPart,
    pub one_time_pre_keys: Vec<OtpkPart>,
    pub created_at_utc: String,
    pub expires_at_utc: String,
}

struct VerifiedBundle {
    identity: IdentityKey,
    registration_id: u32,
    device_id: u32,
    signed_id: SignedPreKeyId,
    signed_pub: PublicKey,
    signed_sig: Vec<u8>,
    kyber_id: KyberPreKeyId,
    kyber_pub: kem::PublicKey,
    kyber_sig: Vec<u8>,
    otpks: Vec<(PreKeyId, PublicKey)>,
}

fn verify_bundle(b: &Bundle) -> Result<VerifiedBundle, String> {
    if b.protocol != PROTOCOL_NAME {
        return Err(format!("unsupported protocol '{}'", b.protocol));
    }
    if b.format_version != BUNDLE_FORMAT_VERSION {
        return Err(format!("unsupported bundle format version {}", b.format_version));
    }
    if b.registration_id == 0 || b.registration_id > 16383 {
        return Err("registrationId out of range".to_string());
    }
    if b.device_id == 0 || b.device_id > 127 {
        return Err("deviceId out of range".to_string());
    }
    let identity = IdentityKey::try_from(b64d(&b.identity_public_key)?.as_slice())
        .map_err(|e| format!("identityPublicKey: {e}"))?;
    if b.fingerprint != fingerprint_of(identity.public_key()) {
        return Err("fingerprint does not match identity public key".to_string());
    }

    let signed_pub = PublicKey::deserialize(&b64d(&b.signed_pre_key.public_key)?)
        .map_err(|e| format!("signedPreKey.publicKey: {e}"))?;
    let signed_sig = b64d(&b.signed_pre_key.signature)?;
    if !identity
        .public_key()
        .verify_signature(&signed_pub.serialize(), &signed_sig)
    {
        return Err("signed pre-key signature verification failed".to_string());
    }
    if b.signed_pre_key.id == 0 {
        return Err("signedPreKey.id must be > 0".to_string());
    }

    let kyber_pub = kem::PublicKey::deserialize(&b64d(&b.kyber_pre_key.public_key)?)
        .map_err(|e| format!("kyberPreKey.publicKey: {e}"))?;
    let kyber_sig = b64d(&b.kyber_pre_key.signature)?;
    if !identity
        .public_key()
        .verify_signature(&kyber_pub.serialize(), &kyber_sig)
    {
        return Err("kyber pre-key signature verification failed".to_string());
    }
    if b.kyber_pre_key.id == 0 {
        return Err("kyberPreKey.id must be > 0".to_string());
    }

    if b.one_time_pre_keys.len() > MAX_OTPK_IMPORT {
        return Err("too many one-time pre-keys in bundle".to_string());
    }
    let mut seen = std::collections::HashSet::new();
    let mut otpks = Vec::with_capacity(b.one_time_pre_keys.len());
    for o in &b.one_time_pre_keys {
        if o.id == 0 || !seen.insert(o.id) {
            return Err(format!("duplicate or invalid one-time pre-key id {}", o.id));
        }
        let pk = PublicKey::deserialize(&b64d(&o.public_key)?)
            .map_err(|e| format!("oneTimePreKeys[{}]: {e}", o.id))?;
        otpks.push((PreKeyId::from(o.id), pk));
    }

    let now = now_secs();
    let created = parse_utc(&b.created_at_utc)?;
    let expires = parse_utc(&b.expires_at_utc)?;
    if created > now + 300 {
        return Err("bundle createdAtUtc is in the future".to_string());
    }
    if expires <= created || expires <= now {
        return Err("bundle is expired".to_string());
    }
    if expires - created > 400 * 86400 {
        return Err("bundle validity period too long".to_string());
    }

    Ok(VerifiedBundle {
        identity,
        registration_id: b.registration_id,
        device_id: b.device_id,
        signed_id: SignedPreKeyId::from(b.signed_pre_key.id),
        signed_pub,
        signed_sig,
        kyber_id: KyberPreKeyId::from(b.kyber_pre_key.id),
        kyber_pub,
        kyber_sig,
        otpks,
    })
}

fn bundle_from_req(req: &Value) -> Result<Bundle, String> {
    let v = req.get("bundle").ok_or("missing field 'bundle'")?;
    serde_json::from_value(v.clone()).map_err(|e| format!("malformed bundle: {e}"))
}

// ── dispatch ─────────────────────────────────────────────────────────────────

pub fn run(op: &str, req: &Value) -> Result<Value, String> {
    match op {
        "identity.generate" => identity_generate(),
        "bundle.create" => bundle_create(req),
        "bundle.validate" => bundle_validate(req),
        "session.init" => session_init(req),
        "encrypt" => encrypt(req),
        "decrypt" => decrypt(req),
        "kdf.argon2id" => kdf_argon2id(req),
        "aead.seal" => aead_seal(req),
        "aead.open" => aead_open(req),
        "random" => random_bytes(req),
        "fingerprint" => fingerprint_op(req),
        _ => Err(format!("unknown op '{op}'")),
    }
}

fn identity_generate() -> Result<Value, String> {
    let mut rng = rand::rng();
    let pair = IdentityKeyPair::generate(&mut rng);
    let registration_id: u32 = rng.random_range(1..=16380);
    Ok(json!({
        "identityKeyPair": b64e(&pair.serialize()),
        "identityPublicKey": b64e(&pair.identity_key().serialize()),
        "registrationId": registration_id,
        "fingerprint": fingerprint_of(pair.public_key()),
    }))
}

fn bundle_create(req: &Value) -> Result<Value, String> {
    let pair = identity_pair(req)?;
    let registration_id = req_u32(req, "registrationId")?;
    if registration_id == 0 || registration_id > 16383 {
        return Err("registrationId out of range".to_string());
    }
    let device_id = opt_u32(req, "deviceId", 1)?;
    let signed_id = req_u32(req, "signedPreKeyId")?;
    let kyber_id = req_u32(req, "kyberPreKeyId")?;
    let otpk_start = req_u32(req, "oneTimePreKeyStartId")?;
    let otpk_count = opt_u32(req, "oneTimePreKeyCount", 20)?;
    let validity_days = opt_u32(req, "validityDays", 30)?;
    if signed_id == 0 || kyber_id == 0 || otpk_start == 0 {
        return Err("pre-key ids must be > 0".to_string());
    }
    if otpk_count > MAX_OTPK_EXPORT {
        return Err(format!("oneTimePreKeyCount must be <= {MAX_OTPK_EXPORT}"));
    }
    if validity_days == 0 || validity_days > 365 {
        return Err("validityDays must be 1..=365".to_string());
    }
    if otpk_count > 0 && otpk_start as u64 + otpk_count as u64 - 1 > u32::MAX as u64 {
        return Err("one-time pre-key id overflow".to_string());
    }

    let mut rng = rand::rng();
    let now = SystemTime::now();
    let now_ms = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

    let signed_kp = libsignal_protocol::KeyPair::generate(&mut rng);
    let signed_sig = pair
        .private_key()
        .calculate_signature(&signed_kp.public_key.serialize(), &mut rng)
        .map_err(|e| format!("signing signed pre-key: {e}"))?;
    let signed_record = SignedPreKeyRecord::new(
        SignedPreKeyId::from(signed_id),
        Timestamp::from_epoch_millis(now_ms),
        &signed_kp,
        &signed_sig,
    );

    let kyber_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        KyberPreKeyId::from(kyber_id),
        pair.private_key(),
    )
    .map_err(|e| format!("generating kyber pre-key: {e}"))?;

    let mut otpk_records = Vec::with_capacity(otpk_count as usize);
    let mut otpk_public = Vec::with_capacity(otpk_count as usize);
    for i in 0..otpk_count {
        let id = otpk_start + i;
        let kp = libsignal_protocol::KeyPair::generate(&mut rng);
        let record = PreKeyRecord::new(PreKeyId::from(id), &kp);
        otpk_public.push(OtpkPart {
            id,
            public_key: b64e(&record.public_key().map_err(|e| e.to_string())?.serialize()),
        });
        otpk_records.push(json!({ "id": id, "record": b64e(&record.serialize().map_err(|e| e.to_string())?) }));
    }

    let created = now_secs();
    let bundle = Bundle {
        protocol: PROTOCOL_NAME.to_string(),
        format_version: BUNDLE_FORMAT_VERSION,
        registration_id,
        device_id,
        identity_public_key: b64e(&pair.identity_key().serialize()),
        fingerprint: fingerprint_of(pair.public_key()),
        signed_pre_key: SignedPart {
            id: signed_id,
            public_key: b64e(&signed_kp.public_key.serialize()),
            signature: b64e(&signed_sig),
        },
        kyber_pre_key: SignedPart {
            id: kyber_id,
            public_key: b64e(&kyber_record.public_key().map_err(|e| e.to_string())?.serialize()),
            signature: b64e(&kyber_record.signature().map_err(|e| e.to_string())?),
        },
        one_time_pre_keys: otpk_public,
        created_at_utc: format_utc(created),
        expires_at_utc: format_utc(created + validity_days as u64 * 86400),
    };

    // Self-check: the exported bundle must pass our own import validation.
    verify_bundle(&bundle)?;

    Ok(json!({
        "bundle": bundle,
        "private": {
            "signedPreKeyRecord": b64e(&signed_record.serialize().map_err(|e| e.to_string())?),
            "kyberPreKeyRecord": b64e(&kyber_record.serialize().map_err(|e| e.to_string())?),
            "oneTimePreKeys": otpk_records,
        }
    }))
}

fn bundle_validate(req: &Value) -> Result<Value, String> {
    let b = bundle_from_req(req)?;
    let v = verify_bundle(&b)?;
    Ok(json!({
        "ok": true,
        "fingerprint": b.fingerprint,
        "registrationId": v.registration_id,
        "deviceId": v.device_id,
        "oneTimePreKeyCount": v.otpks.len(),
        "expiresAtUtc": b.expires_at_utc,
    }))
}

fn make_identity_store(
    req: &Value,
    remote: &ProtocolAddress,
) -> Result<IdentityStore, String> {
    let pair = identity_pair(req)?;
    let registration_id = req_u32(req, "registrationId")?;
    let expected = IdentityKey::try_from(req_bytes(req, "remoteIdentityPublicKey")?.as_slice())
        .map_err(|e| format!("remoteIdentityPublicKey: {e}"))?;
    Ok(IdentityStore {
        pair,
        registration_id,
        remote_address: remote.clone(),
        expected_remote: expected,
        known: HashMap::new(),
    })
}

fn session_init(req: &Value) -> Result<Value, String> {
    let local = addr(req, "localName", "localDeviceId")?;
    let remote = addr(req, "remoteName", "remoteDeviceId")?;
    let b = bundle_from_req(req)?;
    let v = verify_bundle(&b)?;

    let mut identity = make_identity_store(req, &remote)?;
    if identity.expected_remote != v.identity {
        return Err("remoteIdentityPublicKey does not match bundle identity".to_string());
    }
    let mut sessions = Sessions { map: HashMap::new() };

    // Pick one one-time pre-key from the bundle (random spread). The receiver
    // learns the consumed id from the incoming PreKeySignalMessage itself.
    let mut rng = rand::rng();
    let chosen = if v.otpks.is_empty() {
        None
    } else {
        Some(v.otpks[rng.random_range(0..v.otpks.len())].clone())
    };
    let selected_id = chosen.as_ref().map(|(id, _)| u32::from(*id));

    let bundle = PreKeyBundle::new(
        v.registration_id,
        DeviceId::new(v.device_id as u8).map_err(|_| "invalid deviceId".to_string())?,
        chosen,
        v.signed_id,
        v.signed_pub,
        v.signed_sig,
        v.kyber_id,
        v.kyber_pub,
        v.kyber_sig,
        v.identity,
    )
    .map_err(|e| format!("PreKeyBundle: {e}"))?;

    block_on(libsignal_protocol::initiate_session(
        &remote,
        &local,
        &mut sessions,
        &mut identity,
        &bundle,
        SystemTime::now(),
        &mut rng,
    ))
    .map_err(|e| format!("initiate_session: {e}"))?;

    let record = block_on(sessions.load_session(&remote))
        .map_err(|e| e.to_string())?
        .ok_or("session was not created")?;
    Ok(json!({
        "sessionRecord": b64e(&record.serialize().map_err(|e| e.to_string())?),
        "selectedOneTimePreKeyId": selected_id,
    }))
}

fn load_sessions(req: &Value, remote: &ProtocolAddress) -> Result<Sessions, String> {
    let mut map = HashMap::new();
    if let Some(bytes) = opt_bytes(req, "sessionRecord")? {
        let record =
            SessionRecord::deserialize(&bytes).map_err(|e| format!("sessionRecord: {e}"))?;
        map.insert(remote.clone(), record);
    }
    Ok(Sessions { map })
}

fn encrypt(req: &Value) -> Result<Value, String> {
    let local = addr(req, "localName", "localDeviceId")?;
    let remote = addr(req, "remoteName", "remoteDeviceId")?;
    let plaintext = req_bytes(req, "plaintext")?;
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err(format!("plaintext must be 1..={MAX_PLAINTEXT} bytes"));
    }
    let mut identity = make_identity_store(req, &remote)?;
    let mut sessions = load_sessions(req, &remote)?;
    if sessions.map.is_empty() {
        return Err("no session: establish a session from an imported bundle first".to_string());
    }

    let mut rng = rand::rng();
    let ct = block_on(libsignal_protocol::message_encrypt(
        &plaintext,
        &remote,
        &local,
        &mut sessions,
        &mut identity,
        SystemTime::now(),
        &mut rng,
    ))
    .map_err(|e| format!("message_encrypt: {e}"))?;

    let (message_type, serialized): (u8, &[u8]) = match &ct {
        CiphertextMessage::SignalMessage(m) => (CiphertextMessageType::Whisper as u8, m.serialized()),
        CiphertextMessage::PreKeySignalMessage(m) => (CiphertextMessageType::PreKey as u8, m.serialized()),
        other => {
            return Err(format!(
                "unexpected ciphertext type {:?}",
                other.message_type()
            ))
        }
    };

    let record = block_on(sessions.load_session(&remote))
        .map_err(|e| e.to_string())?
        .ok_or("session missing after encrypt")?;
    Ok(json!({
        "sessionRecord": b64e(&record.serialize().map_err(|e| e.to_string())?),
        "ciphertext": b64e(serialized),
        "messageType": message_type,
    }))
}

fn decrypt(req: &Value) -> Result<Value, String> {
    let local = addr(req, "localName", "localDeviceId")?;
    let remote = addr(req, "remoteName", "remoteDeviceId")?;
    let ciphertext = req_bytes(req, "ciphertext")?;
    if ciphertext.is_empty() || ciphertext.len() > 2 * MAX_PLAINTEXT {
        return Err("ciphertext size out of range".to_string());
    }
    let message_type = req_u32(req, "messageType")?;

    let ct = match message_type {
        2 => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext.as_slice())
                .map_err(|e| format!("SignalMessage: {e}"))?,
        ),
        3 => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext.as_slice())
                .map_err(|e| format!("PreKeySignalMessage: {e}"))?,
        ),
        _ => return Err(format!("unsupported messageType {message_type}")),
    };

    let mut identity = make_identity_store(req, &remote)?;
    let mut sessions = load_sessions(req, &remote)?;

    let mut pre_keys = PreKeys { map: HashMap::new(), consumed: None };
    let mut signed = SignedPreKeys { map: HashMap::new() };
    let mut kyber = KyberPreKeys { map: HashMap::new(), consumed: None };

    if message_type == 3 {
        // The caller supplies the locally retained pre-key records as lists;
        // libsignal selects the exact ids referenced by the message. A missing
        // or already-consumed key fails closed inside the protocol stack.
        let signed_list = req
            .get("signedPreKeys")
            .and_then(Value::as_array)
            .ok_or_else(|| "signedPreKeys list required for pre-key messages".to_string())?;
        if signed_list.len() > 200 {
            return Err("too many signed pre-keys".to_string());
        }
        for item in signed_list {
            let id = req_u32(item, "id")?;
            let bytes = req_bytes(item, "record")?;
            let record = SignedPreKeyRecord::deserialize(&bytes)
                .map_err(|e| format!("signedPreKeys[{id}]: {e}"))?;
            let rid = record.id().map_err(|e| e.to_string())?;
            if u32::from(rid) != id {
                return Err(format!("signedPreKeys[{id}]: record id mismatch"));
            }
            signed.map.insert(rid, record);
        }

        let kyber_list = req
            .get("kyberPreKeys")
            .and_then(Value::as_array)
            .ok_or_else(|| "kyberPreKeys list required for pre-key messages".to_string())?;
        if kyber_list.len() > 200 {
            return Err("too many kyber pre-keys".to_string());
        }
        for item in kyber_list {
            let id = req_u32(item, "id")?;
            let bytes = req_bytes(item, "record")?;
            let record = KyberPreKeyRecord::deserialize(&bytes)
                .map_err(|e| format!("kyberPreKeys[{id}]: {e}"))?;
            let rid = record.id().map_err(|e| e.to_string())?;
            if u32::from(rid) != id {
                return Err(format!("kyberPreKeys[{id}]: record id mismatch"));
            }
            kyber.map.insert(rid, record);
        }

        if let Some(list) = req.get("oneTimePreKeys").and_then(Value::as_array) {
            if list.len() > MAX_OTPK_IMPORT {
                return Err("too many one-time pre-keys".to_string());
            }
            for item in list {
                let id = req_u32(item, "id")?;
                let bytes = req_bytes(item, "record")?;
                let record = PreKeyRecord::deserialize(&bytes)
                    .map_err(|e| format!("oneTimePreKeys[{id}]: {e}"))?;
                let rid = record.id().map_err(|e| e.to_string())?;
                if u32::from(rid) != id {
                    return Err(format!("oneTimePreKeys[{id}]: record id mismatch"));
                }
                pre_keys.map.insert(rid, record);
            }
        }
    }

    let mut rng = rand::rng();
    let plaintext = block_on(libsignal_protocol::message_decrypt(
        &ct,
        &remote,
        &local,
        &mut sessions,
        &mut identity,
        &mut pre_keys,
        &signed,
        &mut kyber,
        &mut rng,
    ))
    .map_err(|e| format!("message_decrypt: {e}"))?;

    let record = block_on(sessions.load_session(&remote))
        .map_err(|e| e.to_string())?
        .ok_or("session missing after decrypt")?;

    Ok(json!({
        "plaintext": b64e(&plaintext),
        "sessionRecord": b64e(&record.serialize().map_err(|e| e.to_string())?),
        "consumedOneTimePreKeyId": pre_keys.consumed.map(u32::from),
        "consumedKyberPreKeyId": kyber.consumed.map(u32::from),
    }))
}

fn kdf_argon2id(req: &Value) -> Result<Value, String> {
    let password = req_str(req, "password")?;
    if password.is_empty() || password.len() > 4096 {
        return Err("password must be 1..=4096 bytes".to_string());
    }
    let salt = req_bytes(req, "salt")?;
    if salt.len() < 8 || salt.len() > 64 {
        return Err("salt must be 8..=64 bytes".to_string());
    }
    let m = opt_u32(req, "memoryKiB", 65536)?;
    let t = opt_u32(req, "iterations", 3)?;
    let p = opt_u32(req, "parallelism", 4)?;
    let out_len = opt_u32(req, "outputLen", 32)? as usize;
    if !(8..=1_048_576).contains(&m) || !(1..=16).contains(&t) || !(1..=16).contains(&p) {
        return Err("argon2 parameters out of range".to_string());
    }
    if !(16..=64).contains(&out_len) {
        return Err("outputLen must be 16..=64".to_string());
    }
    let params = argon2::Params::new(m, t, p, Some(out_len)).map_err(|e| format!("params: {e}"))?;
    let kdf = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; out_len];
    kdf.hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| format!("argon2id: {e}"))?;
    Ok(json!({ "key": b64e(&out) }))
}

fn aead_key(req: &Value) -> Result<Vec<u8>, String> {
    let key = req_bytes(req, "key")?;
    if key.len() != 32 {
        return Err("key must be 32 bytes".to_string());
    }
    Ok(key)
}

fn aead_seal(req: &Value) -> Result<Value, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let key = aead_key(req)?;
    let plaintext = req_bytes(req, "plaintext")?;
    if plaintext.len() > MAX_AEAD_PLAINTEXT {
        return Err("plaintext too large".to_string());
    }
    let aad = opt_bytes(req, "aad")?.unwrap_or_default();
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "invalid key".to_string())?;
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let ct = cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload { msg: &plaintext, aad: &aad },
        )
        .map_err(|_| "aead seal failed".to_string())?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ct);
    Ok(json!({ "sealed": b64e(&sealed) }))
}

fn aead_open(req: &Value) -> Result<Value, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let key = aead_key(req)?;
    let sealed = req_bytes(req, "sealed")?;
    if sealed.len() < 24 + 16 || sealed.len() > MAX_AEAD_PLAINTEXT + 24 + 16 {
        return Err("sealed blob size out of range".to_string());
    }
    let aad = opt_bytes(req, "aad")?.unwrap_or_default();
    let (nonce, ct) = sealed.split_at(24);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "invalid key".to_string())?;
    let pt = cipher
        .decrypt(
            chacha20poly1305::XNonce::from_slice(nonce),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| "aead open failed: authentication error (wrong key or tampered data)".to_string())?;
    Ok(json!({ "plaintext": b64e(&pt) }))
}

fn random_bytes(req: &Value) -> Result<Value, String> {
    let n = req_u32(req, "length")? as usize;
    if n == 0 || n > 65536 {
        return Err("length must be 1..=65536".to_string());
    }
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    Ok(json!({ "bytes": b64e(&buf) }))
}

fn fingerprint_op(req: &Value) -> Result<Value, String> {
    let pk = PublicKey::deserialize(&req_bytes(req, "identityPublicKey")?)
        .map_err(|e| format!("identityPublicKey: {e}"))?;
    Ok(json!({ "fingerprint": fingerprint_of(&pk) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_roundtrip() {
        for secs in [0u64, 86399, 86400, 1_700_000_000, 4_102_444_800] {
            let s = format_utc(secs);
            assert_eq!(parse_utc(&s).unwrap(), secs, "{s}");
        }
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert!(parse_utc("2026-11-17T09:00:00Z").is_ok());
        assert!(parse_utc("2026-11-17 09:00:00").is_err());
        assert!(parse_utc("2026-13-17T09:00:00Z").is_err());
    }
}
