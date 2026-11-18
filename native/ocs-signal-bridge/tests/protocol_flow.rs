// End-to-end protocol tests through the public JSON dispatch (same contract
// the C# layer uses). These exercise the official libsignal implementation;
// they are interoperability/lifecycle tests, not homemade crypto proofs.
// SPDX-License-Identifier: AGPL-3.0-only

use base64::Engine;
use serde_json::{json, Value};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn call(op: &str, req: Value) -> Value {
    let resp = ocs_signal_bridge::dispatch(op, &req.to_string())
        .unwrap_or_else(|e| panic!("op {op} failed: {e}"));
    serde_json::from_str(&resp).unwrap()
}

fn call_err(op: &str, req: Value) -> String {
    match ocs_signal_bridge::dispatch(op, &req.to_string()) {
        Ok(ok) => panic!("op {op} unexpectedly succeeded: {ok}"),
        Err(e) => e,
    }
}

fn b64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

fn text(v: &Value, k: &str) -> String {
    String::from_utf8(b64(v[k].as_str().unwrap())).unwrap()
}

struct Party {
    identity: Value,
    bundle: Value,
    private: Value,
    name: String,
}

impl Party {
    fn new(name: &str) -> Party {
        let identity = call("identity.generate", json!({}));
        let created = call(
            "bundle.create",
            json!({
                "identityKeyPair": identity["identityKeyPair"],
                "registrationId": identity["registrationId"],
                "signedPreKeyId": 1,
                "kyberPreKeyId": 1,
                "oneTimePreKeyStartId": 100,
                "oneTimePreKeyCount": 5,
            }),
        );
        Party {
            identity,
            bundle: created["bundle"].clone(),
            private: created["private"].clone(),
            name: name.to_string(),
        }
    }

    fn otpks(&self) -> Value {
        self.private["oneTimePreKeys"].clone()
    }

    fn decrypt_req(&self, from: &Party, session: Option<&str>, ct: &Value) -> Value {
        json!({
            "identityKeyPair": self.identity["identityKeyPair"],
            "registrationId": self.identity["registrationId"],
            "localName": self.name,
            "remoteName": from.name,
            "remoteIdentityPublicKey": from.identity["identityPublicKey"],
            "sessionRecord": session,
            "ciphertext": ct["ciphertext"],
            "messageType": ct["messageType"],
            "signedPreKeys": json!([{
                "id": self.bundle["signedPreKey"]["id"],
                "record": self.private["signedPreKeyRecord"],
            }]),
            "kyberPreKeys": json!([{
                "id": self.bundle["kyberPreKey"]["id"],
                "record": self.private["kyberPreKeyRecord"],
            }]),
            "oneTimePreKeys": self.otpks(),
        })
    }

    fn encrypt_req(&self, to: &Party, session: &str, plaintext: &str) -> Value {
        json!({
            "identityKeyPair": self.identity["identityKeyPair"],
            "registrationId": self.identity["registrationId"],
            "localName": self.name,
            "remoteName": to.name,
            "remoteIdentityPublicKey": to.identity["identityPublicKey"],
            "sessionRecord": session,
            "plaintext": B64.encode(plaintext.as_bytes()),
        })
    }
}

#[test]
fn full_alice_bob_lifecycle() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    // Bob validates and imports Alice's bundle, then initiates a session.
    let validated = call("bundle.validate", json!({ "bundle": alice.bundle }));
    assert_eq!(validated["ok"], true);
    assert_eq!(validated["fingerprint"], alice.identity["fingerprint"]);
    assert_eq!(validated["oneTimePreKeyCount"], 5);

    let init = call(
        "session.init",
        json!({
            "identityKeyPair": bob.identity["identityKeyPair"],
            "registrationId": bob.identity["registrationId"],
            "localName": bob.name,
            "remoteName": alice.name,
            "remoteIdentityPublicKey": alice.identity["identityPublicKey"],
            "bundle": alice.bundle,
        }),
    );
    let bob_session = init["sessionRecord"].as_str().unwrap().to_string();
    let selected_otpk = init["selectedOneTimePreKeyId"].as_u64().unwrap();

    // Bob -> Alice: first message is a pre-key message.
    let ct1 = call("encrypt", bob.encrypt_req(&alice, &bob_session, "hello alice"));
    assert_eq!(ct1["messageType"], 3);
    let bob_session = ct1["sessionRecord"].as_str().unwrap().to_string();

    let pt1 = call("decrypt", alice.decrypt_req(&bob, None, &ct1));
    assert_eq!(text(&pt1, "plaintext"), "hello alice");
    assert_eq!(pt1["consumedOneTimePreKeyId"].as_u64().unwrap(), selected_otpk);
    assert!(pt1["consumedKyberPreKeyId"].as_u64().is_some());
    let alice_session = pt1["sessionRecord"].as_str().unwrap().to_string();

    // Alice -> Bob: reply acknowledges the session (whisper message).
    let ct2 = call("encrypt", alice.encrypt_req(&bob, &alice_session, "hi bob"));
    assert_eq!(ct2["messageType"], 2);
    let alice_session = ct2["sessionRecord"].as_str().unwrap().to_string();
    let pt2 = call("decrypt", bob.decrypt_req(&alice, Some(&bob_session), &ct2));
    assert_eq!(text(&pt2, "plaintext"), "hi bob");
    let bob_session = pt2["sessionRecord"].as_str().unwrap().to_string();

    // Several round trips; both sides keep serialized state in sync.
    let mut bob_session = bob_session;
    let mut alice_session = alice_session;
    for i in 0..6 {
        let msg = format!("bob message {i}");
        let ct = call("encrypt", bob.encrypt_req(&alice, &bob_session, &msg));
        assert_eq!(ct["messageType"], 2);
        bob_session = ct["sessionRecord"].as_str().unwrap().to_string();
        let pt = call("decrypt", alice.decrypt_req(&bob, Some(&alice_session), &ct));
        assert_eq!(text(&pt, "plaintext"), msg);
        alice_session = pt["sessionRecord"].as_str().unwrap().to_string();

        let reply = format!("alice reply {i}");
        let ct = call("encrypt", alice.encrypt_req(&bob, &alice_session, &reply));
        alice_session = ct["sessionRecord"].as_str().unwrap().to_string();
        let pt = call("decrypt", bob.decrypt_req(&alice, Some(&bob_session), &ct));
        assert_eq!(text(&pt, "plaintext"), reply);
        bob_session = pt["sessionRecord"].as_str().unwrap().to_string();
    }

    // Out-of-order delivery within the skipped-message window still works.
    let c1 = call("encrypt", bob.encrypt_req(&alice, &bob_session, "ooo-1"));
    let s1 = c1["sessionRecord"].as_str().unwrap().to_string();
    let c2 = call("encrypt", bob.encrypt_req(&alice, &s1, "ooo-2"));
    let bob_session = c2["sessionRecord"].as_str().unwrap().to_string();
    let p2 = call("decrypt", alice.decrypt_req(&bob, Some(&alice_session), &c2));
    assert_eq!(text(&p2, "plaintext"), "ooo-2");
    let alice_session = p2["sessionRecord"].as_str().unwrap().to_string();
    let p1 = call("decrypt", alice.decrypt_req(&bob, Some(&alice_session), &c1));
    assert_eq!(text(&p1, "plaintext"), "ooo-1");
    let _ = bob_session;
}

#[test]
fn tampered_bundle_is_rejected() {
    let alice = Party::new("alice");
    let mut bad = alice.bundle.clone();

    // Flip one byte of the signed pre-key signature.
    let mut sig = b64(bad["signedPreKey"]["signature"].as_str().unwrap());
    sig[0] ^= 0x01;
    bad["signedPreKey"]["signature"] = json!(B64.encode(&sig));
    let e = call_err("bundle.validate", json!({ "bundle": bad }));
    assert!(e.contains("signature"), "{e}");

    // Flip one byte of the kyber signature.
    let mut bad = alice.bundle.clone();
    let mut sig = b64(bad["kyberPreKey"]["signature"].as_str().unwrap());
    sig[10] ^= 0x80;
    bad["kyberPreKey"]["signature"] = json!(B64.encode(&sig));
    let e = call_err("bundle.validate", json!({ "bundle": bad }));
    assert!(e.contains("signature"), "{e}");

    // Swap in a different identity key: fingerprint check must fail.
    let eve = Party::new("eve");
    let mut bad = alice.bundle.clone();
    bad["identityPublicKey"] = eve.identity["identityPublicKey"].clone();
    let e = call_err("bundle.validate", json!({ "bundle": bad }));
    assert!(e.contains("fingerprint") || e.contains("signature"), "{e}");

    // Unknown protocol / version / unknown fields are rejected strictly.
    let mut bad = alice.bundle.clone();
    bad["protocol"] = json!("static-shared-key");
    assert!(call_err("bundle.validate", json!({ "bundle": bad })).contains("protocol"));
    let mut bad = alice.bundle.clone();
    bad["formatVersion"] = json!(99);
    assert!(call_err("bundle.validate", json!({ "bundle": bad })).contains("version"));
    let mut bad = alice.bundle.clone();
    bad["extraField"] = json!(1);
    assert!(call_err("bundle.validate", json!({ "bundle": bad })).contains("malformed"));

    // Expired bundle.
    let mut bad = alice.bundle.clone();
    bad["expiresAtUtc"] = json!("2020-01-01T00:00:00Z");
    assert!(call_err("bundle.validate", json!({ "bundle": bad })).contains("expired"));

    // Duplicate OTPK ids.
    let mut bad = alice.bundle.clone();
    let first = bad["oneTimePreKeys"][0].clone();
    bad["oneTimePreKeys"].as_array_mut().unwrap().push(first);
    assert!(call_err("bundle.validate", json!({ "bundle": bad })).contains("duplicate"));
}

#[test]
fn consumed_otpk_cannot_be_reused() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");

    // Force a specific OTPK by giving Bob a bundle with exactly that one.
    let mut bundle = alice.bundle.clone();
    let otpk = bundle["oneTimePreKeys"][0].clone();
    let otpk_id = otpk["id"].as_u64().unwrap();
    bundle["oneTimePreKeys"] = json!([otpk]);

    let init = call(
        "session.init",
        json!({
            "identityKeyPair": bob.identity["identityKeyPair"],
            "registrationId": bob.identity["registrationId"],
            "localName": bob.name,
            "remoteName": alice.name,
            "remoteIdentityPublicKey": alice.identity["identityPublicKey"],
            "bundle": bundle,
        }),
    );
    let bob_session = init["sessionRecord"].as_str().unwrap().to_string();
    let ct = call("encrypt", bob.encrypt_req(&alice, &bob_session, "first use"));
    let pt = call("decrypt", alice.decrypt_req(&bob, None, &ct));
    assert_eq!(text(&pt, "plaintext"), "first use");
    assert_eq!(pt["consumedOneTimePreKeyId"].as_u64().unwrap(), otpk_id);
    let alice_session = pt["sessionRecord"].as_str().unwrap().to_string();

    // Bob re-initiates from the SAME bundle (same OTPK) and sends again.
    // Alice has consumed that OTPK: decryption must fail closed.
    let init2 = call(
        "session.init",
        json!({
            "identityKeyPair": bob.identity["identityKeyPair"],
            "registrationId": bob.identity["registrationId"],
            "localName": bob.name,
            "remoteName": alice.name,
            "remoteIdentityPublicKey": alice.identity["identityPublicKey"],
            "bundle": bundle,
        }),
    );
    let bob_session2 = init2["sessionRecord"].as_str().unwrap().to_string();
    let ct2 = call("encrypt", bob.encrypt_req(&alice, &bob_session2, "replay init"));
    let mut req = alice.decrypt_req(&bob, Some(&alice_session), &ct2);
    // Remove the consumed OTPK from Alice's available material, as the C#
    // repository does after marking it consumed.
    let remaining: Vec<Value> = alice.otpks().as_array().unwrap().iter()
        .filter(|k| k["id"].as_u64().unwrap() != otpk_id)
        .cloned().collect();
    req["oneTimePreKeys"] = json!(remaining);
    let e = call_err("decrypt", req);
    assert!(e.contains("message_decrypt"), "{e}");
}

#[test]
fn wrong_remote_identity_is_rejected() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");
    let eve = Party::new("eve");

    let init = call(
        "session.init",
        json!({
            "identityKeyPair": bob.identity["identityKeyPair"],
            "registrationId": bob.identity["registrationId"],
            "localName": bob.name,
            "remoteName": alice.name,
            "remoteIdentityPublicKey": alice.identity["identityPublicKey"],
            "bundle": alice.bundle,
        }),
    );
    let bob_session = init["sessionRecord"].as_str().unwrap().to_string();
    let ct = call("encrypt", bob.encrypt_req(&alice, &bob_session, "secret"));

    // Alice expects Eve's identity instead of Bob's: must fail closed.
    let mut req = alice.decrypt_req(&bob, None, &ct);
    req["remoteIdentityPublicKey"] = eve.identity["identityPublicKey"].clone();
    let e = call_err("decrypt", req);
    assert!(e.contains("message_decrypt"), "{e}");

    // Encrypting to a contact whose pinned identity differs must also fail.
    let mut req = bob.encrypt_req(&alice, &bob_session, "secret2");
    req["remoteIdentityPublicKey"] = eve.identity["identityPublicKey"].clone();
    let e = call_err("encrypt", req);
    assert!(e.contains("message_encrypt"), "{e}");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let alice = Party::new("alice");
    let bob = Party::new("bob");
    let init = call(
        "session.init",
        json!({
            "identityKeyPair": bob.identity["identityKeyPair"],
            "registrationId": bob.identity["registrationId"],
            "localName": bob.name,
            "remoteName": alice.name,
            "remoteIdentityPublicKey": alice.identity["identityPublicKey"],
            "bundle": alice.bundle,
        }),
    );
    let bob_session = init["sessionRecord"].as_str().unwrap().to_string();
    let ct = call("encrypt", bob.encrypt_req(&alice, &bob_session, "attack at dawn"));
    let mut raw = b64(ct["ciphertext"].as_str().unwrap());
    let last = raw.len() - 1;
    raw[last] ^= 0xff; // corrupt the MAC
    let mut bad = ct.clone();
    bad["ciphertext"] = json!(B64.encode(&raw));
    let e = call_err("decrypt", alice.decrypt_req(&bob, None, &bad));
    assert!(e.contains("message_decrypt"), "{e}");
}

#[test]
fn kdf_and_aead() {
    // Argon2id: deterministic, salt-sensitive, parameter-sensitive.
    let salt = B64.encode([7u8; 16]);
    let req = json!({ "password": "correct horse battery staple", "salt": salt,
                      "memoryKiB": 8192, "iterations": 2, "parallelism": 1 });
    let k1 = call("kdf.argon2id", req.clone());
    let k2 = call("kdf.argon2id", req.clone());
    assert_eq!(k1["key"], k2["key"]);
    assert_eq!(b64(k1["key"].as_str().unwrap()).len(), 32);

    let mut other_salt = req.clone();
    other_salt["salt"] = json!(B64.encode([8u8; 16]));
    assert_ne!(call("kdf.argon2id", other_salt)["key"], k1["key"]);

    let mut wrong_pw = req.clone();
    wrong_pw["password"] = json!("wrong password");
    assert_ne!(call("kdf.argon2id", wrong_pw.clone())["key"], k1["key"]);

    // AEAD roundtrip + tamper + wrong key + AAD binding.
    let key = k1["key"].clone();
    let sealed = call(
        "aead.seal",
        json!({ "key": key, "plaintext": B64.encode(b"attack at dawn"), "aad": B64.encode(b"ctx") }),
    )["sealed"].clone();
    let opened = call(
        "aead.open",
        json!({ "key": key, "sealed": sealed, "aad": B64.encode(b"ctx") }),
    );
    assert_eq!(text(&opened, "plaintext"), "attack at dawn");

    let mut raw = b64(sealed.as_str().unwrap());
    raw[30] ^= 1;
    let e = call_err(
        "aead.open",
        json!({ "key": key, "sealed": B64.encode(&raw), "aad": B64.encode(b"ctx") }),
    );
    assert!(e.contains("authentication"), "{e}");

    let e = call_err(
        "aead.open",
        json!({ "key": key, "sealed": sealed, "aad": B64.encode(b"other") }),
    );
    assert!(e.contains("authentication"), "{e}");

    let other_key = call("kdf.argon2id", wrong_pw)["key"].clone();
    let e = call_err("aead.open", json!({ "key": other_key, "sealed": sealed }));
    assert!(e.contains("authentication"), "{e}");
}

#[test]
fn fingerprint_stability_and_limits() {
    let alice = Party::new("alice");
    let fp = call(
        "fingerprint",
        json!({ "identityPublicKey": alice.identity["identityPublicKey"] }),
    );
    assert_eq!(fp["fingerprint"], alice.identity["fingerprint"]);
    let s = fp["fingerprint"].as_str().unwrap();
    assert_eq!(s.replace(' ', "").len(), 64);

    // Oversized / malformed inputs are rejected, never panic.
    assert!(call_err("random", json!({ "length": 0 })).contains("length"));
    assert!(call_err("random", json!({ "length": 70000 })).contains("length"));
    assert!(call_err("aead.seal", json!({ "key": B64.encode([0u8; 31]), "plaintext": "" })).contains("32"));
    assert!(call_err("fingerprint", json!({ "identityPublicKey": B64.encode([0u8; 5]) })).contains("identityPublicKey"));
    assert!(call_err("nonexistent.op", json!({})).contains("unknown op"));
}
